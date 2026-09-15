/* ═══════════════════════════════════════════════════════════════════════════
   auth.js — Authentication, RBAC, DB Layer, IP Guard, Audit Logging
   Planner Internal v2.0 | Acme Corp
   ═══════════════════════════════════════════════════════════════════════════
   SECURITY NOTES:
   • Passwords hashed with multi-round djb2 + salt — suitable for local/internal use.
   • IP restriction enforced at TWO layers:
       1. server.js — blocks non-whitelisted IPs at the HTTP layer (primary)
       2. auth.js   — client-side UX guard shows Access Denied screen as fallback
   • Session stored in sessionStorage (auto-cleared on tab/browser close).
   • All mutations written to auditLog in the JSON DB.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const DB_KEY      = 'planner-db-v2';
const SESSION_KEY = 'planner-session-v2';
const DB_SEED     = 'db.json';

// ─── Password Hashing (synchronous, 3-round djb2) ────────────────────────────
// NOTE: In production use bcrypt/argon2 via a secure backend endpoint.
function _djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(16).padStart(8, '0');
}

function hashPassword(password, salt) {
  const r1 = _djb2(salt + ':' + password + ':planner-2026');
  const r2 = _djb2(password + ':' + r1 + ':internal');
  const r3 = _djb2(r1 + r2 + ':' + salt);
  return r1 + r2 + r3; // 24-char hex
}

function genToken() {
  return [...Array(32)].map(() => Math.floor(Math.random() * 36).toString(36)).join('');
}

function uid() { return Math.random().toString(36).slice(2, 10); }

function nowISO() { return new Date().toISOString(); }

// ─── DB Class ─────────────────────────────────────────────────────────────────
class PlannerDB {
  constructor() { this._data = null; }

  // ── Bootstrap: load seed from db.json → hash seed passwords → save ──────
  async init() {
    // Try localStorage first
    const raw = localStorage.getItem(DB_KEY);
    if (raw) {
      try { this._data = JSON.parse(raw); } catch (_) { this._data = null; }
    }

    // If no local data, fetch seed
    if (!this._data) {
      try {
        const res = await fetch(DB_SEED);
        this._data = await res.json();
      } catch (_) {
        // Fetch failed (offline / opened via file://). Build minimal DB.
        console.warn('[Planner] Could not fetch db.json, using inline defaults.');
        this._data = this._inlineSeed();
      }
    }

    // Hash any unhashed seed passwords
    let changed = false;
    (this._data.users || []).forEach(u => {
      if (u._seedPassword) {
        u.passwordHash = hashPassword(u._seedPassword, u.id);
        delete u._seedPassword;
        changed = true;
      }
    });

    if (changed) this.save();
    return this;
  }

  save() {
    localStorage.setItem(DB_KEY, JSON.stringify(this._data));
  }

  // ── Helpers ──────────────────────────────────────────────────────────────
  getConfig()  { return this._data.config || {}; }
  getRoles()   { return this._data.roles  || {}; }

  // ── Users ─────────────────────────────────────────────────────────────────
  getUsers()              { return this._data.users || []; }
  getUserById(id)         { return this.getUsers().find(u => u.id === id) || null; }
  getUserByUsername(name) { return this.getUsers().find(u => u.username === name) || null; }

  createUser(data) {
    const user = {
      id: 'u' + uid(),
      username: data.username,
      passwordHash: hashPassword(data.password, 'u' + uid()),
      displayName: data.displayName,
      email: data.email,
      role: data.role || 'viewer',
      department: data.department || '',
      avatar: (data.displayName || data.username).split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase(),
      active: true,
      failedAttempts: 0,
      lockedUntil: null,
      createdAt: nowISO().split('T')[0],
      lastLogin: null,
      createdBy: data.createdBy || 'system',
      mustChangePassword: data.mustChangePassword || false,
    };
    // Fix: hash with the actual id now
    user.passwordHash = hashPassword(data.password, user.id);
    this._data.users.push(user);
    this.save();
    return user;
  }

  updateUser(id, patch) {
    const u = this.getUserById(id);
    if (!u) return null;
    Object.assign(u, patch);
    this.save();
    return u;
  }

  changePassword(id, newPassword) {
    const u = this.getUserById(id);
    if (!u) return false;
    u.passwordHash = hashPassword(newPassword, u.id);
    u.mustChangePassword = false;
    this.save();
    return true;
  }

  recordLoginAttempt(id, success) {
    const u = this.getUserById(id);
    if (!u) return;
    const cfg = this.getConfig();
    if (success) {
      u.failedAttempts = 0;
      u.lockedUntil = null;
      u.lastLogin = nowISO();
    } else {
      u.failedAttempts = (u.failedAttempts || 0) + 1;
      if (u.failedAttempts >= (cfg.maxLoginAttempts || 5)) {
        const lockMins = cfg.lockoutMinutes || 15;
        u.lockedUntil = new Date(Date.now() + lockMins * 60000).toISOString();
      }
    }
    this.save();
  }

  // ── Projects ──────────────────────────────────────────────────────────────
  getProjects()   { return this._data.projects || []; }
  getProjectById(id) { return this.getProjects().find(p => p.id === id) || null; }

  createProject(data) {
    const proj = {
      id: 'p' + uid(),
      name: data.name,
      description: data.description || '',
      color: data.color || '#ff5c3b',
      status: data.status || 'active',
      createdAt: nowISO().split('T')[0],
      createdBy: data.createdBy,
      tasks: [],
    };
    this._data.projects.push(proj);
    this.save();
    return proj;
  }

  updateProject(id, patch) {
    const p = this.getProjectById(id);
    if (!p) return null;
    Object.assign(p, patch);
    this.save();
    return p;
  }

  deleteProject(id) {
    const idx = this._data.projects.findIndex(p => p.id === id);
    if (idx < 0) return false;
    this._data.projects.splice(idx, 1);
    this.save();
    return true;
  }

  // Task helpers on a project
  addTask(projectId, data) {
    const p = this.getProjectById(projectId);
    if (!p) return null;
    const task = {
      id: 't' + uid(),
      name: data.name,
      description: data.description || '',
      status: data.status || 'todo',
      priority: data.priority || 'medium',
      startDate: data.startDate || '',
      dueDate: data.dueDate || '',
      progress: data.progress || 0,
      assignee: data.assignee || '',
      tags: data.tags || [],
      issues: [],
      createdBy: data.createdBy || '',
      createdAt: nowISO().split('T')[0],
    };
    p.tasks.push(task);
    this.save();
    return task;
  }

  updateTask(projectId, taskId, patch) {
    const p = this.getProjectById(projectId);
    if (!p) return null;
    const t = p.tasks.find(t => t.id === taskId);
    if (!t) return null;
    Object.assign(t, patch);
    this.save();
    return t;
  }

  deleteTask(projectId, taskId) {
    const p = this.getProjectById(projectId);
    if (!p) return false;
    const idx = p.tasks.findIndex(t => t.id === taskId);
    if (idx < 0) return false;
    p.tasks.splice(idx, 1);
    this.save();
    return true;
  }

  addIssue(projectId, taskId, data) {
    const p = this.getProjectById(projectId);
    const t = p?.tasks.find(t => t.id === taskId);
    if (!t) return null;
    const issue = { id: 'i' + uid(), text: data.text, severity: data.severity || 'medium', resolved: false, createdAt: nowISO().split('T')[0], createdBy: data.createdBy || '' };
    t.issues.push(issue);
    this.save();
    return issue;
  }

  updateIssue(projectId, taskId, issueId, patch) {
    const p = this.getProjectById(projectId);
    const t = p?.tasks.find(t => t.id === taskId);
    const i = t?.issues.find(i => i.id === issueId);
    if (!i) return null;
    Object.assign(i, patch);
    this.save();
    return i;
  }

  // ── Audit Log ─────────────────────────────────────────────────────────────
  getAuditLog() { return (this._data.auditLog || []).slice().reverse(); }

  log(action, detail, userId, category = 'general') {
    const entry = {
      id: 'al' + uid(),
      timestamp: nowISO(),
      userId,
      action,
      detail,
      category,
      ip: window._clientIP || 'unknown',
    };
    if (!this._data.auditLog) this._data.auditLog = [];
    this._data.auditLog.push(entry);
    // Keep last 500 entries
    if (this._data.auditLog.length > 500) this._data.auditLog.shift();
    this.save();
    return entry;
  }

  exportDB() {
    const blob = new Blob([JSON.stringify(this._data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `planner-db-export-${Date.now()}.json`;
    a.click();
  }

  resetDB() {
    localStorage.removeItem(DB_KEY);
    location.reload();
  }

  // ── Inline seed fallback (if db.json not fetchable via file://) ───────────
  _inlineSeed() {
    return {
      config: { orgName:'Acme Corp', orgDomain:'acmecorp.internal', logoInitials:'AC', allowedHosts:['localhost','127.0.0.1'], devMode:true, sessionTimeoutMinutes:480, maxLoginAttempts:5, lockoutMinutes:15, passwordMinLength:8, version:'2.0.0' },
      roles: {
        superadmin: { label:'Super Admin',   color:'#ef4444', description:'Unrestricted access', permissions:['*'] },
        admin:      { label:'Administrator', color:'#ff5c3b', description:'Full project and user management', permissions:['projects.view','projects.create','projects.edit','projects.delete','tasks.create','tasks.edit','tasks.delete','issues.manage','analytics.view','timeline.view','cicd.view','iam.view','iam.manage','audit.view'] },
        manager:    { label:'Manager',       color:'#f59e0b', description:'Manage projects and tasks', permissions:['projects.view','projects.create','projects.edit','tasks.create','tasks.edit','tasks.delete','issues.manage','analytics.view','timeline.view','cicd.view'] },
        developer:  { label:'Developer',     color:'#06b6d4', description:'Edit tasks and log issues', permissions:['projects.view','tasks.create','tasks.edit','issues.manage','timeline.view','cicd.view'] },
        viewer:     { label:'Viewer',        color:'#64748b', description:'Read-only access',  permissions:['projects.view','analytics.view','timeline.view'] },
      },
      users: [
        { id:'u1', username:'admin',      _seedPassword:'Admin@123',       passwordHash:null, displayName:'System Administrator', email:'admin@acmecorp.internal',   role:'admin',      department:'IT Operations', avatar:'SA', active:true, failedAttempts:0, lockedUntil:null, createdAt:'2026-01-01', lastLogin:null, createdBy:'system', mustChangePassword:false },
        { id:'u2', username:'manager1',   _seedPassword:'Manager@123',     passwordHash:null, displayName:'Priya Sharma',         email:'priya@acmecorp.internal',   role:'manager',    department:'Product',       avatar:'PS', active:true, failedAttempts:0, lockedUntil:null, createdAt:'2026-01-10', lastLogin:null, createdBy:'u1',     mustChangePassword:false },
        { id:'u3', username:'dev1',       _seedPassword:'Dev@123',         passwordHash:null, displayName:'Karan Patel',          email:'karan@acmecorp.internal',   role:'developer',  department:'Engineering',   avatar:'KP', active:true, failedAttempts:0, lockedUntil:null, createdAt:'2026-01-15', lastLogin:null, createdBy:'u1',     mustChangePassword:false },
        { id:'u4', username:'viewer1',    _seedPassword:'Viewer@123',      passwordHash:null, displayName:'Rahul Mehta',          email:'rahul@acmecorp.internal',   role:'viewer',     department:'Management',    avatar:'RM', active:true, failedAttempts:0, lockedUntil:null, createdAt:'2026-02-01', lastLogin:null, createdBy:'u1',     mustChangePassword:false },
        { id:'u5', username:'superadmin', _seedPassword:'Super@Admin2026', passwordHash:null, displayName:'Root Admin',           email:'root@acmecorp.internal',    role:'superadmin', department:'IT Operations', avatar:'RA', active:true, failedAttempts:0, lockedUntil:null, createdAt:'2026-01-01', lastLogin:null, createdBy:'system', mustChangePassword:false },
      ],
      projects: [],
      auditLog: [],
    };
  }
}

// ─── Auth Class ───────────────────────────────────────────────────────────────
class PlannerAuth {
  constructor(db) {
    this.db = db;
    this._session = null;
    this._loadSession();
  }

  // ── IP Guard ──────────────────────────────────────────────────────────────
  checkIPAccess() {
    const cfg = this.db.getConfig();
    if (cfg.devMode) return true; // Always allow in dev mode
    const host = window.location.hostname;
    const allowed = cfg.allowedHosts || [];
    return allowed.includes(host) || host === 'localhost' || host === '127.0.0.1';
  }

  // ── Login ─────────────────────────────────────────────────────────────────
  login(username, password) {
    const user = this.db.getUserByUsername(username.trim().toLowerCase());
    const ERR_INVALID = 'Invalid username or password.';

    if (!user) return { ok: false, error: ERR_INVALID };
    if (!user.active) return { ok: false, error: 'Account is deactivated. Contact your administrator.' };

    // Check lockout
    if (user.lockedUntil) {
      if (new Date(user.lockedUntil) > new Date()) {
        const mins = Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000);
        return { ok: false, error: `Account locked. Try again in ${mins} minute(s).` };
      } else {
        this.db.updateUser(user.id, { lockedUntil: null, failedAttempts: 0 });
      }
    }

    // Verify password
    const hash = hashPassword(password, user.id);
    if (hash !== user.passwordHash) {
      this.db.recordLoginAttempt(user.id, false);
      const remaining = (this.db.getConfig().maxLoginAttempts || 5) - (user.failedAttempts + 1);
      return { ok: false, error: remaining > 0 ? `${ERR_INVALID} ${remaining} attempt(s) remaining.` : 'Account locked due to too many failed attempts.' };
    }

    // Success
    this.db.recordLoginAttempt(user.id, true);
    const token = genToken();
    const cfg = this.db.getConfig();
    const expires = Date.now() + (cfg.sessionTimeoutMinutes || 480) * 60000;
    this._session = { token, userId: user.id, username: user.username, role: user.role, expires };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(this._session));
    this.db.log('LOGIN', `User "${user.username}" logged in`, user.id, 'auth');
    return { ok: true, user };
  }

  logout() {
    if (this._session) {
      this.db.log('LOGOUT', `User "${this._session.username}" logged out`, this._session.userId, 'auth');
    }
    this._session = null;
    sessionStorage.removeItem(SESSION_KEY);
  }

  _loadSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) {
        const sess = JSON.parse(raw);
        if (sess.expires > Date.now()) this._session = sess;
        else sessionStorage.removeItem(SESSION_KEY);
      }
    } catch (_) {}
  }

  isLoggedIn() {
    if (!this._session) return false;
    if (this._session.expires <= Date.now()) { this.logout(); return false; }
    return true;
  }

  getSession()     { return this._session; }
  getCurrentUser() { return this._session ? this.db.getUserById(this._session.userId) : null; }

  // ── RBAC Permission Check ─────────────────────────────────────────────────
  can(permission) {
    if (!this.isLoggedIn()) return false;
    const user = this.getCurrentUser();
    if (!user || !user.active) return false;
    const roles = this.db.getRoles();
    const role = roles[user.role];
    if (!role) return false;
    const perms = role.permissions || [];
    return perms.includes('*') || perms.includes(permission);
  }

  // Convenience: throw if no permission
  require(permission) {
    if (!this.can(permission)) throw new Error(`Permission denied: ${permission}`);
  }
}

// ─── IP Detection (best-effort) ───────────────────────────────────────────────
window._clientIP = window.location.hostname;

// ─── Exports ──────────────────────────────────────────────────────────────────
window.PlannerDB   = PlannerDB;
window.PlannerAuth = PlannerAuth;
window.hashPassword = hashPassword;
