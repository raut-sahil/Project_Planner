/* ═══════════════════════════════════════════════════════════════════════════
   PLANNER — server.js
   Internal Org Project Command Center — Secure Node.js Backend
   IAM + RBAC + IP Restriction + JWT Auth + JSON File Database
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

require('dotenv').config();
const { ProxyAgent, setGlobalDispatcher } = require('undici');
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}
const express   = require('express');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');
const { v4: uuidv4 } = require('uuid');
const PDFDocument = require('pdfkit');

const LOGO_PATH = path.join(__dirname, 'assets', 'fligen-logo.png');

const app  = express();
const PORT = process.env.PORT || 3000;

function resolveWritableDbPath() {
  if (process.env.DB_PATH) return path.resolve(process.env.DB_PATH);

  const isPkg = !!process.pkg;
  const externalDir = isPkg
    ? path.join(path.dirname(process.execPath))
    : __dirname; 

  const externalDbPath = path.join(externalDir, 'db.json');

  if (!fs.existsSync(externalDbPath)) {
    // Pull the seed shipped inside the exe (or the plain file when not packaged)
    const seedPath = path.join(__dirname, 'db.json');
    try {
      const seedData = fs.readFileSync(seedPath, 'utf8');
      fs.writeFileSync(externalDbPath, seedData, 'utf8');
      console.log(`[DB] Seeded fresh db.json at ${externalDbPath}`);
    } catch (e) {
      console.error('[DB] Failed to seed db.json:', e.message);
    }
  }

  return externalDbPath;
}

const DB_PATH = resolveWritableDbPath();
const JWT_SECRET  = process.env.JWT_SECRET || 'INSECURE_DEFAULT_CHANGE_THIS_IN_PRODUCTION';
const JWT_EXPIRY  = process.env.JWT_EXPIRY || '8h';
const ALLOWED_IP  = process.env.ALLOWED_IP  || '127.0.0.1';
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '').split(',').map(s=>s.trim()).filter(Boolean);
// All configured entries (single IPs or CIDR subnets like 192.168.1.0/24 or 10.0.0.0/8)
const ALL_ENTRIES = [ALLOWED_IP, ...ALLOWED_IPS, '127.0.0.1', '::1'];

app.use('/__neutralino_globals.js', express.static(path.join(__dirname, 'bin', '__neutralino_globals.js')));

/* ─── CIDR Subnet Matching ─────────────────────────────────────────────────── */
function ipToInt(ip) {
  // Handles IPv4 only; IPv6 subnets not supported (use exact IP for those)
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return null;
  return (parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) >>> 0;
}

function isIPv4(ip) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

function matchesCIDR(ip, cidr) {
  if (!cidr.includes('/')) {
    // Exact match — strip ::ffff: prefix for IPv4-mapped IPv6
    const cleanIP   = ip.replace(/^::ffff:/, '');
    const cleanCIDR = cidr.replace(/^::ffff:/, '');
    return cleanIP === cleanCIDR || ip === cidr;
  }
  const [network, bits] = cidr.split('/');
  const prefixLen = parseInt(bits, 10);
  if (isNaN(prefixLen) || !isIPv4(network)) return false;

  // Normalise the incoming IP (strip IPv4-mapped IPv6 prefix)
  const cleanIP = ip.replace(/^::ffff:/, '');
  if (!isIPv4(cleanIP)) return false;

  const ipInt   = ipToInt(cleanIP);
  const netInt  = ipToInt(network);
  if (ipInt === null || netInt === null) return false;

  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function isAllowed(ip) {
  // Always allow localhost variants
  const clean = ip.replace(/^::ffff:/, '');
  if (clean === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  return ALL_ENTRIES.some(entry => matchesCIDR(clean, entry) || matchesCIDR(ip, entry));
}
const MAX_ATTEMPTS    = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
const LOCKOUT_SECONDS = parseInt(process.env.LOCKOUT_SECONDS || '900');

/* ─── RBAC Permission Map ──────────────────────────────────────────────────── */
const PERMISSIONS = {
  superadmin: [
    'projects:read','projects:create','projects:update','projects:delete',
    'tasks:read','tasks:create','tasks:update','tasks:delete',
    'issues:read','issues:create','issues:update','issues:resolve',
    'users:read','users:create','users:update','users:delete',
    'audit:read','settings:manage'
  ],
  admin: [
    'projects:read','projects:create','projects:update','projects:delete',
    'tasks:read','tasks:create','tasks:update','tasks:delete',
    'issues:read','issues:create','issues:update','issues:resolve',
    'users:read','audit:read'
  ],
  manager: [
    'projects:read','projects:create','projects:update',
    'tasks:read','tasks:create','tasks:update','tasks:delete',
    'issues:read','issues:create','issues:update','issues:resolve',
    'users:read'
  ],
  developer: [
    'projects:read',
    'tasks:read','tasks:update',
    'issues:read','issues:create','issues:resolve'
  ],
  viewer: [
    'projects:read','tasks:read','issues:read'
  ]
};

function can(user, permission) {
  return (PERMISSIONS[user.role] || []).includes(permission);
}

/* ─── Database Helpers ─────────────────────────────────────────────────────── */
function readDB() {
  try {
    const raw = fs.readFileSync(path.resolve(DB_PATH), 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('[DB] Read error:', e.message);
    throw new Error('Database unavailable');
  }
}

function writeDB(data) {
  try {
    fs.writeFileSync(path.resolve(DB_PATH), JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[DB] Write error:', e.message);
    throw new Error('Database write failed');
  }
}

function audit(db, action, user, details, ip) {
  db.auditLog = db.auditLog || [];
  db.auditLog.unshift({
    id: 'al' + uuidv4().slice(0,8),
    action,
    userId:   user ? user.id   : 'system',
    userName: user ? user.name : 'System',
    role:     user ? user.role : '-',
    details,
    ip: ip || '?',
    timestamp: new Date().toISOString()
  });
  // Keep last 500 entries
  if (db.auditLog.length > 500) db.auditLog = db.auditLog.slice(0, 500);
}

/* ─── Middleware ───────────────────────────────────────────────────────────── */
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// IP Restriction — subnet-aware allowlist (supports CIDR like 192.168.1.0/24)
app.use((req, res, next) => {
  const forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const clientIP  = forwarded || req.socket.remoteAddress || '';

  if (!isAllowed(clientIP)) {
    const clean = clientIP.replace(/^::ffff:/, '');
    console.warn(`[SECURITY] Blocked ${clean} — not in allowlist [${ALL_ENTRIES.join(', ')}]`);
    return res.status(403).json({
      error:   'Access denied',
      message: 'This system is restricted to the authorized internal network.'
    });
  }
  req.clientIP = clientIP.replace(/^::ffff:/, '') || clientIP;
  next();
});

// CORS — allow same-origin and any origin within the permitted subnet
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // direct / server-rendered
    try {
      const host = new URL(origin).hostname;
      if (isAllowed(host)) return cb(null, true);
    } catch (_) {}
    // Fallback: allow localhost always
    // Allow any origin that resolves to an allowed IP/subnet
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) return cb(null, true);
    // For LAN access the origin will be e.g. http://192.168.1.42:3000 — already checked above via isAllowed(host)
    return cb(null, true); // Trust the IP allowlist; CORS is not the security boundary here
  },
  credentials: true
}));

// Serve static frontend files — supports flat layout (all files together) OR public/ subdir
const publicDir = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
  ? path.join(__dirname, 'public')
  : __dirname;
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(publicDir));

// JWT Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db   = readDB();
    const user = db.users.find(u => u.id === decoded.sub && u.active);
    if (!user) return res.status(401).json({ error: 'User not found or inactive' });
    req.user = user;
    req.db   = db;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Permission guard factory
function requirePerm(permission) {
  return (req, res, next) => {
    if (!can(req.user, permission)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Your role (${req.user.role}) does not have permission: ${permission}`
      });
    }
    next();
  };
}

function getCompletedTasksForMonth(db, since, until) {
  const sinceT = new Date(since).getTime();
  const untilT = new Date(until).getTime();
  const rows = [];
  (db.projects || []).forEach(proj => {
    (proj.tasks || []).forEach(t => {
      if (t.status !== 'done') return;
      const completedAt = t.completedAt || t.updatedAt || t.dueDate || t.createdAt;
      if (!completedAt) return;
      const ct = new Date(completedAt).getTime();
      if (isNaN(ct) || ct < sinceT || ct >= untilT) return;
      rows.push({
        date: new Date(completedAt).toISOString(),
        project: proj.name,
        summary: `Task completed: ${t.name}`,
        source: 'task'
      });
    });
  });
  return rows;
}

/* ═══════════════════════════════════════════════════════════════════════════
   AUTH ROUTES
   ═══════════════════════════════════════════════════════════════════════════ */

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const db   = readDB();
    const user = db.users.find(u =>
      (u.username === username || u.email === username) && u.active
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Lockout check
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const wait = Math.ceil((new Date(user.lockedUntil) - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${wait} minute(s).` });
    }

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= MAX_ATTEMPTS) {
        user.lockedUntil = new Date(Date.now() + LOCKOUT_SECONDS * 1000).toISOString();
        audit(db, 'ACCOUNT_LOCKED', user, `Locked after ${MAX_ATTEMPTS} failed attempts`, req.clientIP);
      }
      audit(db, 'LOGIN_FAIL', user, `Failed login attempt ${user.loginAttempts}`, req.clientIP);
      writeDB(db);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Success
    user.loginAttempts = 0;
    user.lockedUntil   = null;
    user.lastLogin     = new Date().toISOString();
    audit(db, 'LOGIN_SUCCESS', user, 'Successful login', req.clientIP);
    writeDB(db);

    const token = jwt.sign(
      { sub: user.id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    const { password: _, loginAttempts: __, lockedUntil: ___, ...safeUser } = user;
    res.json({ token, user: safeUser, permissions: PERMISSIONS[user.role] || [] });

  } catch (e) {
    console.error('[AUTH] Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password, loginAttempts, lockedUntil, ...safeUser } = req.user;
  res.json({ user: safeUser, permissions: PERMISSIONS[req.user.role] || [] });
});

// POST /api/auth/logout
app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const db = readDB();
  audit(db, 'LOGOUT', req.user, 'User logged out', req.clientIP);
  writeDB(db);
  res.json({ message: 'Logged out' });
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both current and new password required' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    const db   = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!bcrypt.compareSync(currentPassword, user.password)) {
      return res.status(401).json({ error: 'Current password incorrect' });
    }
    user.password = bcrypt.hashSync(newPassword, 12);
    audit(db, 'PASSWORD_CHANGED', req.user, 'Password changed', req.clientIP);
    writeDB(db);
    res.json({ message: 'Password changed successfully' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ═══════════════════════════════════════════════════════════════════════════
   USER ROUTES
   ═══════════════════════════════════════════════════════════════════════════ */

// GET /api/users
app.get('/api/users', authMiddleware, requirePerm('users:read'), (req, res) => {
  const db = readDB();
  const safe = db.users.map(({ password, loginAttempts, lockedUntil, ...u }) => u);
  res.json(safe);
});

// POST /api/users
app.post('/api/users', authMiddleware, requirePerm('users:create'), (req, res) => {
  try {
    const { username, email, name, role, department, password } = req.body;
    if (!username || !email || !name || !role || !password) {
      return res.status(400).json({ error: 'username, email, name, role, password required' });
    }
    const validRoles = Object.keys(PERMISSIONS);
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: `Invalid role. Valid: ${validRoles.join(', ')}` });
    }
    // Superadmin can only be created by superadmin
    if (role === 'superadmin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can create superadmin accounts' });
    }
    const db = readDB();
    if (db.users.find(u => u.username === username || u.email === email)) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    const newUser = {
      id: 'u' + uuidv4().slice(0,8),
      username, email, name,
      role, department: department || '',
      avatar: name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(),
      password: bcrypt.hashSync(password, 12),
      active: true,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      createdBy: req.user.id,
      loginAttempts: 0,
      lockedUntil: null
    };
    db.users.push(newUser);
    audit(db, 'USER_CREATED', req.user, `Created user ${username} (${role})`, req.clientIP);
    writeDB(db);
    const { password: _, loginAttempts: __, lockedUntil: ___, ...safe } = newUser;
    res.status(201).json(safe);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/users/:id
app.put('/api/users/:id', authMiddleware, requirePerm('users:update'), (req, res) => {
  try {
    const db   = readDB();
    const user = db.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Only superadmin can edit superadmin accounts
    if (user.role === 'superadmin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Cannot modify superadmin accounts' });
    }
    // Cannot demote yourself
    if (user.id === req.user.id && req.body.role && req.body.role !== user.role) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }

    const allowed = ['name','email','department','role','active'];
    allowed.forEach(f => { if (req.body[f] !== undefined) user[f] = req.body[f]; });

    // Password reset by admin
    if (req.body.newPassword && req.user.role === 'superadmin') {
      user.password = bcrypt.hashSync(req.body.newPassword, 12);
      user.loginAttempts = 0;
      user.lockedUntil   = null;
    }
    // Unlock account
    if (req.body.unlock && can(req.user, 'users:update')) {
      user.loginAttempts = 0;
      user.lockedUntil   = null;
    }

    audit(db, 'USER_UPDATED', req.user, `Updated user ${user.username}`, req.clientIP);
    writeDB(db);
    const { password: _, loginAttempts: __, lockedUntil: ___, ...safe } = user;
    res.json(safe);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', authMiddleware, requirePerm('users:delete'), (req, res) => {
  try {
    const db   = readDB();
    const idx  = db.users.findIndex(u => u.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (db.users[idx].id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    const [removed] = db.users.splice(idx, 1);
    audit(db, 'USER_DELETED', req.user, `Deleted user ${removed.username}`, req.clientIP);
    writeDB(db);
    res.json({ message: 'User deleted' });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ═══════════════════════════════════════════════════════════════════════════
   PROJECT ROUTES
   ═══════════════════════════════════════════════════════════════════════════ */

// GET /api/projects
app.get('/api/projects', authMiddleware, requirePerm('projects:read'), (req, res) => {
  const db = readDB();
  res.json(db.projects);
});

// POST /api/projects
app.post('/api/projects', authMiddleware, requirePerm('projects:create'), (req, res) => {
  try {
    const { name, description, color, status } = req.body;
    if (!name) return res.status(400).json({ error: 'Project name required' });
    const db = readDB();
    const project = {
      id: 'p' + uuidv4().slice(0,8),
      name: name.trim(),
      description: (description || '').trim(),
      color: color || '#f59e0b',
      status: status || 'active',
      createdAt: new Date().toISOString(),
      createdBy: req.user.id,
      createdByName: req.user.name,
      tasks: []
    };
    db.projects.push(project);
    audit(db, 'PROJECT_CREATED', req.user, `Created project "${name}"`, req.clientIP);
    writeDB(db);
    res.status(201).json(project);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/projects/:id
app.put('/api/projects/:id', authMiddleware, requirePerm('projects:update'), (req, res) => {
  try {
    const db  = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });

    // Managers can only edit projects they created
    if (req.user.role === 'manager' && proj.createdBy !== req.user.id) {
      return res.status(403).json({ error: 'You can only edit projects you created' });
    }

    const editable = ['name','description','color','status'];
    editable.forEach(f => { if (req.body[f] !== undefined) proj[f] = req.body[f]; });
    proj.updatedAt = new Date().toISOString();
    proj.updatedBy = req.user.id;

    audit(db, 'PROJECT_UPDATED', req.user, `Updated project "${proj.name}"`, req.clientIP);
    writeDB(db);
    res.json(proj);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/projects/:id
app.delete('/api/projects/:id', authMiddleware, requirePerm('projects:delete'), (req, res) => {
  try {
    const db  = readDB();
    const idx = db.projects.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Project not found' });
    const [removed] = db.projects.splice(idx, 1);
    audit(db, 'PROJECT_DELETED', req.user, `Deleted project "${removed.name}"`, req.clientIP);
    writeDB(db);
    res.json({ message: 'Project deleted' });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});


function parseGithubRepo(input) {
  if (!input) return null;
  const clean = input.trim().replace(/\.git$/, '').replace(/\/+$/, '');
  const m = clean.match(/github\.com[/:]([^/]+)\/([^/]+)/i) || clean.match(/^([^/\s]+)\/([^/\s]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function fetchGithubCommits({ owner, repo, token, branch }, since, until) {
  const params = new URLSearchParams({ per_page: '100' });
  if (branch) params.set('sha', branch);
  if (since)  params.set('since', since);
  if (until)  params.set('until', until);
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?${params}`;
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'planner-command-center' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(url, { headers });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`GitHub ${resp.status} for ${owner}/${repo}@${branch || '(default)'}: ${body.slice(0, 200)}`);
  }
  const data = await resp.json();
  return data.map(c => {
    const fullMessage = c.commit.message.trim();
    return {
      sha: c.sha.slice(0, 7),
      message: fullMessage,                          // full commit message (subject + body)
      summary: fullMessage.split('\n')[0],            // subject line only, for places that need one line
      author: c.commit.author?.name || c.author?.login || 'unknown',
      date: c.commit.author?.date || c.commit.committer?.date,
      url: c.html_url
    };
  });
}

async function fetchGithubBranches({ owner, repo, token }) {
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'planner-command-center' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/branches?per_page=100`, { headers });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`GitHub ${resp.status} for ${owner}/${repo}: ${body.slice(0, 200)}`);
  }
  const data = await resp.json();
  return data.map(b => b.name);
}

async function fetchGithubRepoInfo({ owner, repo, token }) {
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'planner-command-center' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  if (!resp.ok) {
    if (resp.status === 404) {
      throw new Error(
        token
          ? `Repo "${owner}/${repo}" not found (404) — check the token has access, or the owner/repo is misspelled.`
          : `Repo "${owner}/${repo}" not found (404) — if it's private, add a personal access token.`
      );
    }
    const body = await resp.text().catch(() => '');
    throw new Error(`GitHub ${resp.status} for ${owner}/${repo}: ${body.slice(0, 200)}`);
  }
  return resp.json();
}

function buildJobCardPDF(res, { monthLabel, employeeName, rows }) {
  const doc = new PDFDocument({ size: 'A4', margin: 24 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="Job-Card-${monthLabel.replace(/\s+/g, '-')}.pdf"`);
  doc.pipe(res);

  const marginX = doc.page.margins.left;
  const pageWidth = doc.page.width - marginX * 2;

  // ── Header block: logo | Job Card | doc-info box ──
  const logoW = 130, docBoxW = 150;
  const titleW = pageWidth - logoW - docBoxW;
  const headerTop = doc.y;
  const headerH = 66;

  doc.rect(marginX, headerTop, logoW, headerH).stroke();
  doc.rect(marginX + logoW, headerTop, titleW, headerH).stroke();
  doc.rect(marginX + logoW + titleW, headerTop, docBoxW, headerH).stroke();

  try {
    if (fs.existsSync(LOGO_PATH)) {
      doc.image(LOGO_PATH, marginX + 12, headerTop + 16, { width: logoW - 24 });
    }
  } catch (_) { /* logo optional */ }

  doc.font('Helvetica').fontSize(13)
     .text('Job Card', marginX + logoW, headerTop + headerH / 2 - 8, { width: titleW, align: 'center' });

  const docBoxX = marginX + logoW + titleW;
  doc.fontSize(8);
  doc.text('DOC. NO.: FSPL/INT/11', docBoxX + 6, headerTop + 5, { width: docBoxW - 12 });
  doc.text('REV.: 00', docBoxX + 6, headerTop + 21, { width: docBoxW - 12 });
  doc.text('REV. DATE: 01.07.2024', docBoxX + 6, headerTop + 37, { width: docBoxW - 12 });
  [16, 32, 48].forEach(dy => doc.moveTo(docBoxX, headerTop + dy).lineTo(docBoxX + docBoxW, headerTop + dy).stroke());

  let y = headerTop + headerH + 6;

  // ── Name / Month row ──
  const nameRowH = 20;
  doc.rect(marginX, y, pageWidth, nameRowH).stroke();
  doc.font('Helvetica-Bold').fontSize(9)
     .text(`Name: ${employeeName || ''}`, marginX + 6, y + 6, { width: pageWidth / 2 });
  doc.text(`Month: ${monthLabel}`, marginX + pageWidth / 2, y + 6, { width: pageWidth / 2 - 6, align: 'right' });
  y += nameRowH;

  // ── Table columns (Work Time collapsed to a single Commit Time column) ──
  const cols = [
    { key: 'sr',   label: 'SR\nNo',       width: 28 },
    { key: 'date', label: 'DATE',         width: 58 },
    { key: 'work', label: 'Work Done',     width: 222 },
    { key: 'time', label: 'Commit Time',         width: 55 },
    { key: 'sign', label: 'Sign',         width: 40 },
  ];
  const sumW = cols.reduce((s, c) => s + c.width, 0);
  cols[2].width += pageWidth - sumW; // pad Work Done so columns fill the page exactly

  const colX = i => marginX + cols.slice(0, i).reduce((s, c) => s + c.width, 0);

  function drawHeaderRow(yy) {
    const rowH = 26;
    doc.rect(marginX, yy, pageWidth, rowH).fillAndStroke('#dce3f7', '#000000');
    doc.fillColor('#000').font('Helvetica-Bold').fontSize(8);
    cols.forEach((c, i) => {
      doc.rect(colX(i), yy, c.width, rowH).stroke();
      doc.text(c.label, colX(i) + 2, yy + (c.label.includes('\n') ? 4 : 8), { width: c.width - 4, align: 'center' });
    });
    return yy + rowH;
  }

  y = drawHeaderRow(y);
  doc.font('Helvetica').fontSize(8).fillColor('#000');

  const bottomLimit = doc.page.height - doc.page.margins.bottom;

  if (!rows.length) {
    doc.rect(marginX, y, pageWidth, 24).stroke();
    doc.text('No job card entries found for this period.', marginX + 6, y + 8, { width: pageWidth - 12, align: 'center' });
    y += 24;
  }

  rows.forEach((r, idx) => {
    const workHeight = doc.heightOfString(r.work || '', { width: cols[2].width - 6 });
    const rowH = Math.max(20, workHeight + 8);

    if (y + rowH > bottomLimit) {
      doc.addPage();
      y = drawHeaderRow(doc.page.margins.top);
      doc.font('Helvetica').fontSize(8).fillColor('#000');
    }

    // Sign is left blank intentionally — filled in by hand
    const vals = [String(idx + 1), r.date, r.work, r.time, ''];
    cols.forEach((c, i) => {
      doc.rect(colX(i), y, c.width, rowH).stroke();
      if (vals[i]) doc.text(vals[i], colX(i) + 3, y + 4, { width: c.width - 6, align: i === 2 ? 'left' : 'center' });
    });
    y += rowH;
  });

  // ── Big "Extras:" notes box below the table (filled in by hand) ──
  const extrasBoxH = 90;
  const gapAfterExtras = 60; // increased spacing before the signature line
  if (y + extrasBoxH + gapAfterExtras + 20 > bottomLimit) {
    doc.addPage();
    y = doc.page.margins.top;
  } else {
    y += 8;
  }
  doc.rect(marginX, y, pageWidth, extrasBoxH).stroke();
  doc.font('Helvetica-Bold').fontSize(9).text('Extras:', marginX + 6, y + 6);
  y += extrasBoxH + gapAfterExtras;

  // ── Supervisor Sign & Date — single field at the end of the document ──
  const sigLineW = 220;
  const sigLineX = marginX + pageWidth - sigLineW;
  doc.font('Helvetica').fontSize(9);
  doc.moveTo(sigLineX, y).lineTo(sigLineX + sigLineW, y).stroke();
  doc.text('Supervisor Sign & Date', sigLineX, y + 4, { width: sigLineW, align: 'center' });

  doc.end();
}

/* ─── Task Routes ──────────────────────────────────────────────────────────── */

// POST /api/github/branches — look up branches for a repo BEFORE connecting it
app.post('/api/github/branches', authMiddleware, requirePerm('projects:update'), async (req, res) => {
  try {
    const parsed = parseGithubRepo(req.body.repoUrl);
    if (!parsed) return res.status(400).json({ error: 'Could not parse GitHub repo — use owner/repo or a full github.com URL' });
    const token = req.body.token || '';

    // Fetch repo info first — its error message distinguishes "not found" from "private/needs token"
    const info = await fetchGithubRepoInfo({ ...parsed, token });
    const branches = await fetchGithubBranches({ ...parsed, token });

    res.json({
      owner: parsed.owner,
      repo: parsed.repo,
      branches,
      defaultBranch: info?.default_branch || branches[0] || null
    });
  } catch (e) {
    res.status(502).json({ error: e.message || 'Failed to fetch branches from GitHub' });
  }
});

// GET /api/projects/:id/github/branches — refresh branch list for an already-connected repo
app.get('/api/projects/:id/github/branches', authMiddleware, requirePerm('projects:read'), async (req, res) => {
  try {
    const db = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    if (!proj.github) return res.status(400).json({ error: 'No GitHub repo connected for this project' });

    const branches = await fetchGithubBranches(proj.github);
    res.json({ branches, current: proj.github.branch });
  } catch (e) {
    res.status(502).json({ error: e.message || 'Failed to fetch branches from GitHub' });
  }
});

// PUT /api/projects/:id/github — connect a repo, or switch the branch of an already-connected one
app.put('/api/projects/:id/github', authMiddleware, requirePerm('projects:update'), (req, res) => {
  try {
    const db = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });

    // Branch-only switch on an already-connected repo (no repoUrl sent)
    if (proj.github && req.body.branch && !req.body.repoUrl) {
      proj.github.branch = req.body.branch;
      proj.github.updatedAt = new Date().toISOString();
      audit(db, 'GITHUB_BRANCH_CHANGED', req.user, `Switched "${proj.name}" to branch "${req.body.branch}"`, req.clientIP);
      writeDB(db);
      return res.json({ ...proj.github, token: undefined });
    }

    const parsed = parseGithubRepo(req.body.repoUrl);
    if (!parsed) return res.status(400).json({ error: 'Could not parse GitHub repo — use owner/repo or a full github.com URL' });
    if (!req.body.branch) {
      return res.status(400).json({ error: 'Branch is required — fetch branches and select one before connecting' });
    }

    const keepToken = proj.github && proj.github.owner === parsed.owner && proj.github.repo === parsed.repo
      ? proj.github.token : '';

    proj.github = {
      owner: parsed.owner,
      repo: parsed.repo,
      branch: req.body.branch,
      token: req.body.token || keepToken || '',
      connectedAt: new Date().toISOString(),
      connectedBy: req.user.id
    };
    proj.updatedAt = new Date().toISOString();

    audit(db, 'GITHUB_CONNECTED', req.user, `Connected GitHub repo ${parsed.owner}/${parsed.repo} (branch "${req.body.branch}") to "${proj.name}"`, req.clientIP);
    writeDB(db);
    res.json({ ...proj.github, token: undefined });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/projects/:id/github — disconnect
app.delete('/api/projects/:id/github', authMiddleware, requirePerm('projects:update'), (req, res) => {
  try {
    const db = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    delete proj.github;
    proj.updatedAt = new Date().toISOString();
    audit(db, 'GITHUB_DISCONNECTED', req.user, `Disconnected GitHub repo from "${proj.name}"`, req.clientIP);
    writeDB(db);
    res.json({ message: 'Disconnected' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/projects/:id/github/commits?since=&until=
app.get('/api/projects/:id/github/commits', authMiddleware, requirePerm('projects:read'), async (req, res) => {
  try {
    const db = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    if (!proj.github) return res.status(400).json({ error: 'No GitHub repo connected for this project' });

    const commits = await fetchGithubCommits(proj.github, req.query.since, req.query.until);
    res.json(commits);
  } catch (e) {
    res.status(502).json({ error: e.message || 'Failed to fetch commits from GitHub' });
  }
});

// GET /api/reports/job-card?month=2026-09&format=csv
app.get('/api/reports/job-card', authMiddleware, requirePerm('projects:read'), async (req, res) => {
  try {
    const month = req.query.month; // "YYYY-MM"
    if (!/^\d{4}-\d{2}$/.test(month || '')) {
      return res.status(400).json({ error: 'month must be in YYYY-MM format' });
    }
    const sinceDate = new Date(`${month}-01T00:00:00Z`);
    const untilDate = new Date(sinceDate);
    untilDate.setUTCMonth(untilDate.getUTCMonth() + 1);
    const since = sinceDate.toISOString();
    const until = untilDate.toISOString();

    const requestedSources = (req.query.sources ? req.query.sources.split(',') : ['commits', 'tasks', 'custom'])
      .map(s => s.trim()).filter(Boolean);
    const wants = s => requestedSources.includes(s);

    const db = readDB();
    db.jobEntries = db.jobEntries || [];

    const allEntries = [];

    // ── Commits (GitHub-connected projects) ──
    if (wants('commits')) {
      const connectedProjects = db.projects.filter(p => p.github);
      for (const proj of connectedProjects) {
        try {
          const commits = await fetchGithubCommits(proj.github, since, until);
          commits.forEach(c => allEntries.push({
            date: c.date,
            project: proj.name,
            summary: c.summary || c.message,
            source: 'commit'
          }));
        } catch (e) {
          console.error(`[job-card] Failed for project ${proj.name}:`, e.message);
        }
      }
    }

    // ── Completed tasks ──
    if (wants('tasks')) {
      allEntries.push(...getCompletedTasksForMonth(db, since, until));
    }

    // ── Custom manual entries ──
    if (wants('custom')) {
      db.jobEntries
        .filter(e => (e.date || '').startsWith(month))
        .forEach(e => allEntries.push({
          date: new Date(`${e.date}T00:00:00Z`).toISOString(),
          project: e.projectName || '',
          summary: e.description,
          source: 'custom'
        }));
    }

    allEntries.sort((a, b) => new Date(a.date) - new Date(b.date));

    if (req.query.format === 'pdf') {
      const monthLabel = sinceDate.toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
      const rows = allEntries.map(c => ({
        date: new Date(c.date).toLocaleDateString('en-GB', { timeZone: 'UTC' }),
        time: c.source === 'commit'
          ? new Date(c.date).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
          : '',
        work: `${c.project ? `[${c.project}] ` : ''}${c.summary}`
      }));
      return buildJobCardPDF(res, { monthLabel, employeeName: req.user.name, rows });
    }

    const byDate = {};
    allEntries.forEach(c => {
      const d = (c.date || '').slice(0, 10);
      if (!d) return;
      (byDate[d] ||= []).push(`${c.project ? `[${c.project}] ` : ''}${c.summary}`);
    });

    const rows = Object.keys(byDate).sort().map(date => ({
      date,
      jobDescription: byDate[date].join('; ')
    }));

    if (req.query.format === 'csv') {
      const esc = s => `"${String(s).replace(/"/g, '""')}"`;
      const csv = ['Date,Job Description', ...rows.map(r => `${esc(r.date)},${esc(r.jobDescription)}`)].join('\r\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="Job-Card-${month}.csv"`);
      return res.send(csv);
    }

    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// GET /api/job-entries?month=YYYY-MM
app.get('/api/job-entries', authMiddleware, requirePerm('projects:read'), (req, res) => {
  try {
    const db = readDB();
    db.jobEntries = db.jobEntries || [];
    let entries = db.jobEntries;
    if (req.query.month) {
      if (!/^\d{4}-\d{2}$/.test(req.query.month)) return res.status(400).json({ error: 'month must be YYYY-MM' });
      entries = entries.filter(e => (e.date || '').startsWith(req.query.month));
    }
    entries = entries.slice().sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    res.json(entries);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// POST /api/job-entries
app.post('/api/job-entries', authMiddleware, requirePerm('tasks:create'), (req, res) => {
  try {
    const { date, description, projectId } = req.body;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date (YYYY-MM-DD) required' });
    if (!description || !description.trim()) return res.status(400).json({ error: 'Description required' });

    const db = readDB();
    db.jobEntries = db.jobEntries || [];
    let projectName = '';
    if (projectId) {
      const proj = db.projects.find(p => p.id === projectId);
      if (!proj) return res.status(404).json({ error: 'Project not found' });
      projectName = proj.name;
    }
    const entry = {
      id: 'je' + uuidv4().slice(0, 8),
      date,
      description: description.trim(),
      projectId: projectId || '',
      projectName,
      createdBy: req.user.id,
      createdByName: req.user.name,
      createdAt: new Date().toISOString()
    };
    db.jobEntries.push(entry);
    audit(db, 'JOB_ENTRY_CREATED', req.user, `Added custom job entry "${entry.description}" (${date})`, req.clientIP);
    writeDB(db);
    res.status(201).json(entry);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// PUT /api/job-entries/:id
app.put('/api/job-entries/:id', authMiddleware, requirePerm('tasks:update'), (req, res) => {
  try {
    const db = readDB();
    db.jobEntries = db.jobEntries || [];
    const entry = db.jobEntries.find(e => e.id === req.params.id);
    if (!entry) return res.status(404).json({ error: 'Job entry not found' });

    const { date, description, projectId } = req.body;
    if (date !== undefined) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
      entry.date = date;
    }
    if (description !== undefined) {
      if (!description.trim()) return res.status(400).json({ error: 'Description required' });
      entry.description = description.trim();
    }
    if (projectId !== undefined) {
      if (projectId) {
        const proj = db.projects.find(p => p.id === projectId);
        if (!proj) return res.status(404).json({ error: 'Project not found' });
        entry.projectId = projectId;
        entry.projectName = proj.name;
      } else {
        entry.projectId = '';
        entry.projectName = '';
      }
    }
    entry.updatedAt = new Date().toISOString();
    audit(db, 'JOB_ENTRY_UPDATED', req.user, `Updated custom job entry "${entry.description}"`, req.clientIP);
    writeDB(db);
    res.json(entry);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// DELETE /api/job-entries/:id
app.delete('/api/job-entries/:id', authMiddleware, requirePerm('tasks:delete'), (req, res) => {
  try {
    const db = readDB();
    db.jobEntries = db.jobEntries || [];
    const idx = db.jobEntries.findIndex(e => e.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Job entry not found' });
    const [removed] = db.jobEntries.splice(idx, 1);
    audit(db, 'JOB_ENTRY_DELETED', req.user, `Deleted custom job entry "${removed.description}"`, req.clientIP);
    writeDB(db);
    res.json({ message: 'Deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// GET /api/commits/calendar?since=&until= — aggregated commit activity across ALL connected repos
app.get('/api/commits/calendar', authMiddleware, requirePerm('projects:read'), async (req, res) => {
  try {
    const until = req.query.until ? new Date(req.query.until) : new Date();
    const since = req.query.since ? new Date(req.query.since) : new Date(until.getTime() - 83 * 24 * 60 * 60 * 1000);

    const db = readDB();
    const connectedProjects = db.projects.filter(p => p.github);

    const byDate = {};
    let total = 0;

    for (const proj of connectedProjects) {
      try {
        const commits = await fetchGithubCommits(proj.github, since.toISOString(), until.toISOString());
        commits.forEach(c => {
          const d = (c.date || '').slice(0, 10);
          if (!d) return;
          (byDate[d] ||= []).push({ sha: c.sha, message: c.message, author: c.author, project: proj.name, projectId: proj.id });
          total++;
        });
      } catch (e) {
        console.error(`[commits/calendar] Failed for project ${proj.name}:`, e.message);
      }
    }

    res.json({ since: since.toISOString(), until: until.toISOString(), byDate, total });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

// POST /api/projects/:id/tasks
app.post('/api/projects/:id/tasks', authMiddleware, requirePerm('tasks:create'), (req, res) => {
  try {
    const db   = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });

        const { name, description, status, priority, startDate, dueDate, completedAt, progress, assignee, tags } = req.body;
    if (!name) return res.status(400).json({ error: 'Task name required' });

    const task = {
      id: 't' + uuidv4().slice(0,8),
      name: name.trim(),
      description: (description||'').trim(),
      status: status || 'todo',
      priority: priority || 'medium',
      startDate: startDate || new Date().toISOString().split('T')[0],
      dueDate: dueDate || '',
      progress: parseInt(progress||'0'),
      assignee: assignee || '',
      tags: Array.isArray(tags) ? tags : (tags||'').split(',').map(s=>s.trim()).filter(Boolean),
      issues: [],
      createdAt: new Date().toISOString(),
      createdBy: req.user.id
    };
    if (task.status === 'done') task.completedAt = completedAt || task.createdAt;
    proj.tasks.push(task);
    audit(db, 'TASK_CREATED', req.user, `Created task "${name}" in "${proj.name}"`, req.clientIP);
    writeDB(db);
    res.status(201).json(task);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/projects/:id/tasks/:tid
app.put('/api/projects/:id/tasks/:tid', authMiddleware, requirePerm('tasks:update'), (req, res) => {
  try {
    const db   = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    const task = proj.tasks.find(t => t.id === req.params.tid);
    if (!task) return res.status(404).json({ error: 'Task not found' });

    const prevStatus = task.status;
    const editable = ['name','description','status','priority','startDate','dueDate','progress','assignee','tags'];
    editable.forEach(f => { if (req.body[f] !== undefined) task[f] = req.body[f]; });
    if (task.status === 'done') task.progress = 100;

    // Completed Date — an explicit value from the UI always wins.
    // Otherwise, auto-stamp only on the not-done -> done transition (or clear on reopen).
    if (req.body.completedAt !== undefined) {
      if (req.body.completedAt === '' || req.body.completedAt === null) {
        delete task.completedAt;
      } else if (!/^\d{4}-\d{2}-\d{2}/.test(req.body.completedAt)) {
        return res.status(400).json({ error: 'Completed Date must be a valid date (YYYY-MM-DD)' });
      } else {
        task.completedAt = req.body.completedAt;
      }
    } else if (task.status === 'done' && prevStatus !== 'done') {
      task.completedAt = new Date().toISOString();
    } else if (task.status !== 'done' && prevStatus === 'done') {
      delete task.completedAt;
    }

    task.updatedAt = new Date().toISOString();

    audit(db, 'TASK_UPDATED', req.user, `Updated task "${task.name}"`, req.clientIP);
    writeDB(db);
    res.json(task);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/projects/:id/tasks/:tid
app.delete('/api/projects/:id/tasks/:tid', authMiddleware, requirePerm('tasks:delete'), (req, res) => {
  try {
    const db   = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    const idx = proj.tasks.findIndex(t => t.id === req.params.tid);
    if (idx === -1) return res.status(404).json({ error: 'Task not found' });
    const [removed] = proj.tasks.splice(idx, 1);
    audit(db, 'TASK_DELETED', req.user, `Deleted task "${removed.name}"`, req.clientIP);
    writeDB(db);
    res.json({ message: 'Task deleted' });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ─── Issue Routes ─────────────────────────────────────────────────────────── */

// POST /api/projects/:id/tasks/:tid/issues
app.post('/api/projects/:id/tasks/:tid/issues', authMiddleware, requirePerm('issues:create'), (req, res) => {
  try {
    const db   = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    if (!proj) return res.status(404).json({ error: 'Project not found' });
    const task = proj.tasks.find(t => t.id === req.params.tid);
    if (!task) return res.status(404).json({ error: 'Task not found' });

    const { text, severity } = req.body;
    if (!text) return res.status(400).json({ error: 'Issue text required' });

    const issue = {
      id: 'i' + uuidv4().slice(0,8),
      text: text.trim(),
      severity: severity || 'medium',
      resolved: false,
      createdAt: new Date().toISOString().split('T')[0],
      createdBy: req.user.id
    };
    task.issues.push(issue);
    audit(db, 'ISSUE_CREATED', req.user, `Logged issue on "${task.name}"`, req.clientIP);
    writeDB(db);
    res.status(201).json(issue);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/projects/:id/tasks/:tid/issues/:iid (resolve/unresolve)
app.put('/api/projects/:id/tasks/:tid/issues/:iid', authMiddleware, requirePerm('issues:resolve'), (req, res) => {
  try {
    const db   = readDB();
    const proj = db.projects.find(p => p.id === req.params.id);
    const task = proj?.tasks.find(t => t.id === req.params.tid);
    const issue = task?.issues.find(i => i.id === req.params.iid);
    if (!issue) return res.status(404).json({ error: 'Issue not found' });
    issue.resolved = req.body.resolved !== undefined ? req.body.resolved : !issue.resolved;
    audit(db, 'ISSUE_UPDATED', req.user, `${issue.resolved?'Resolved':'Reopened'} issue`, req.clientIP);
    writeDB(db);
    res.json(issue);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ─── Audit Log ────────────────────────────────────────────────────────────── */
app.get('/api/audit', authMiddleware, requirePerm('audit:read'), (req, res) => {
  const db = readDB();
  const limit = parseInt(req.query.limit || '100');
  res.json((db.auditLog || []).slice(0, limit));
});

/* ─── Settings ─────────────────────────────────────────────────────────────── */
app.get('/api/settings', authMiddleware, requirePerm('settings:manage'), (req, res) => {
  const db = readDB();
  res.json(db.config || {});
});

app.put('/api/settings', authMiddleware, requirePerm('settings:manage'), (req, res) => {
  try {
    const db = readDB();
    const allowed = ['orgName','allowedIP'];
    allowed.forEach(f => { if (req.body[f] !== undefined) db.config[f] = req.body[f]; });
    audit(db, 'SETTINGS_UPDATED', req.user, 'System settings updated', req.clientIP);
    writeDB(db);
    res.json(db.config);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ─── Health check ─────────────────────────────────────────────────────────── */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

/* ─── SPA Fallback ─────────────────────────────────────────────────────────── */
app.get('*', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

/* ─── Error Handler ────────────────────────────────────────────────────────── */
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Bind to 0.0.0.0 so the server is reachable on all network interfaces.
// Security is enforced by the IP/subnet allowlist above — not by binding to localhost.
app.listen(PORT, '0.0.0.0', () => {
  // Discover local LAN IPs to show helpful startup info
  const os = require('os');
  const lanIPs = Object.values(os.networkInterfaces())
    .flat()
    .filter(i => i.family === 'IPv4' && !i.internal)
    .map(i => i.address);

  console.log(`\n◈  Planner Command Center`);
  console.log(`   Localhost : http://127.0.0.1:${PORT}`);
  if (lanIPs.length) {
    lanIPs.forEach(ip => console.log(`   LAN       : http://${ip}:${PORT}`));
  }
  console.log(`   Allowed   : ${ALL_ENTRIES.join(', ')}`);
  console.log(`   DB        : ${path.resolve(DB_PATH)}`);
  console.log(`   JWT Expiry: ${JWT_EXPIRY}\n`);
});

module.exports = app;
