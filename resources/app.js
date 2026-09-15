/* ═══════════════════════════════════════════════════════════════════════════
   PLANNER — app.js (v2 — IAM + API Edition)
   Full application logic: auth, state, render, charts, modals, events
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

const API_BASE  = 'http://localhost:3000/api';
const THEME_KEY = 'planner-theme';
const TOKEN_KEY = 'planner-token';

/* ─── Status / Priority Configs ─────────────────────────────────────────────── */
const STATUS = {
  'todo':        { label:'To Do',       color:'#64748b', icon:'○' },
  'in-progress': { label:'In Progress', color:'#f59e0b', icon:'◑' },
  'done':        { label:'Done',        color:'#2dd4aa', icon:'●' },
  'blocked':     { label:'Blocked',     color:'#ff4060', icon:'✕' },
};
const PRIORITY = {
  'low':      { label:'Low',      color:'#64748b' },
  'medium':   { label:'Medium',   color:'#38c8f0' },
  'high':     { label:'High',     color:'#f59e0b' },
  'critical': { label:'Critical', color:'#ff4060' },
};
const PROJ_STATUS = {
  'active':    { label:'Active',    css:'badge-success' },
  'on-hold':   { label:'On Hold',   css:'badge-warn'    },
  'completed': { label:'Completed', css:'badge-info'    },
  'cancelled': { label:'Cancelled', css:'badge-danger'  },
};
const SEVERITY = {
  'low':      { color:'#64748b', bg:'var(--bg3)' },
  'medium':   { color:'#38c8f0', bg:'var(--info-bg)' },
  'high':     { color:'#f59e0b', bg:'var(--warn-bg)' },
  'critical': { color:'#ff4060', bg:'var(--danger-bg)' },
};
const PROJ_COLORS = ['#f59e0b','#06b6d4','#a78bfa','#2dd4aa','#f43f5e','#fb923c','#84cc16','#e879f9'];
const ROLE_LABELS = {
  superadmin:'Super Admin', admin:'Admin', manager:'Manager',
  developer:'Developer', viewer:'Viewer'
};
const ROLE_COLORS = {
  superadmin:'#ff4060', admin:'#f59e0b', manager:'#06b6d4',
  developer:'#2dd4aa', viewer:'#8a87a0'
};

/* ─── App State ──────────────────────────────────────────────────────────────── */
const S = {
  token: localStorage.getItem(TOKEN_KEY) || null,
  user: null,
  permissions: [],
  projects: [],
  view: 'dashboard',
  selectedProjectId: null,
  filterStatus: 'all',
  issuesTab: 'open',
  sidebarOpen: true,
  theme: localStorage.getItem(THEME_KEY) || 'dark',
  chartInstances: {},
  iamUsers: [],
  auditLog: [],
  jobEntries: [],
  jobCardMonth: new Date().toISOString().slice(0, 7),
  jobCardSources: { commits: true, tasks: true, custom: true },
};

const DAY_MS = 86400000;
function d2date(s){ const d=new Date(s); d.setHours(0,0,0,0); return d; }
function daysBetween(a,b){ return Math.round((d2date(b)-d2date(a))/DAY_MS); }

/* ─── API Helpers ────────────────────────────────────────────────────────────── */
async function api(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (S.token) headers['Authorization'] = `Bearer ${S.token}`;
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || 'API error'), { status: res.status, data });
  return data;
}

const GET    = (path)        => api('GET',    path);
const POST   = (path, body)  => api('POST',   path, body);
const PUT    = (path, body)  => api('PUT',    path, body);
const DELETE = (path)        => api('DELETE', path);

/* ─── Permission Check ──────────────────────────────────────────────────────── */
function can(permission) {
  return S.permissions.includes(permission);
}

function showPermElements() {
  document.querySelectorAll('[class*="perm-"]').forEach(el => {
    const classes = [...el.classList];
    const permClass = classes.find(c => c.startsWith('perm-'));
    if (!permClass) return;
    const perm = permClass.replace('perm-', '').replace(/-/g, ':');
    el.style.display = can(perm) ? '' : 'none';
  });
}

/* ─── Utility ────────────────────────────────────────────────────────────────── */
function uid() { return Math.random().toString(36).slice(2,10); }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function today() { return new Date().toISOString().split('T')[0]; }
function fmtDate(d) { if(!d) return '—'; return new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); }
function fmtDateTime(d) { if(!d) return '—'; return new Date(d).toLocaleString('en-US',{month:'short',day:'numeric',year:'numeric',hour:'2-digit',minute:'2-digit'}); }
function isOverdue(t) { return t.status !== 'done' && t.dueDate && new Date(t.dueDate) < new Date(); }
function daysLeft(d) { return Math.ceil((new Date(d)-new Date())/86400000); }
function projProgress(p) { if(!p.tasks.length) return 0; return Math.round(p.tasks.reduce((s,t)=>s+t.progress,0)/p.tasks.length); }
function allOverdue() { return S.projects.flatMap(p=>p.tasks.map(t=>({...t,projectName:p.name,projectColor:p.color,projectId:p.id}))).filter(t=>isOverdue(t)); }
function getProject() { return S.projects.find(p=>p.id===S.selectedProjectId); }

/* ─── Theme ──────────────────────────────────────────────────────────────────── */
function applyTheme() {
  document.documentElement.setAttribute('data-theme', S.theme);
  const icon  = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (icon)  icon.textContent  = S.theme === 'dark' ? '☀' : '☾';
  if (label) label.textContent = S.theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}
function toggleTheme() {
  S.theme = S.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, S.theme);
  applyTheme();
  if (S.view === 'analytics') renderContent();
}

/* ─── Toasts ─────────────────────────────────────────────────────────────────── */
function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  const icons = { success:'✓', danger:'✕', info:'i' };
  el.className = `toast ${type}`;
  el.innerHTML = `<span style="font-weight:700;color:var(--${type==='info'?'info':type==='success'?'success':'danger'})">${icons[type]||'i'}</span>${esc(msg)}`;
  container.appendChild(el);
  setTimeout(() => {
    el.style.animation = 'toastOut 0.25s ease forwards';
    setTimeout(() => el.remove(), 260);
  }, 2800);
}

/* ═══════════════════════════════════════════════════════════════════════════
   AUTH
   ═══════════════════════════════════════════════════════════════════════════ */
async function doLogin(username, password) {
  const data = await POST('/auth/login', { username, password });
  S.token       = data.token;
  S.user        = data.user;
  S.permissions = data.permissions || [];
  localStorage.setItem(TOKEN_KEY, data.token);
  return data;
}

async function doLogout() {
  try { await POST('/auth/logout'); } catch(_) {}
  S.token = null; S.user = null; S.permissions = []; S.projects = [];
  localStorage.removeItem(TOKEN_KEY);
  showLogin();
}

async function verifyToken() {
  if (!S.token) return false;
  try {
    const data = await GET('/auth/me');
    S.user        = data.user;
    S.permissions = data.permissions || [];
    return true;
  } catch(e) {
    S.token = null;
    localStorage.removeItem(TOKEN_KEY);
    return false;
  }
}

function showLogin() {
  document.getElementById('login-screen').style.display = '';
  document.getElementById('app').style.display = 'none';
}

function showApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = '';
  updateUserUI();
  showPermElements();
}

function updateUserUI() {
  if (!S.user) return;
  const av    = S.user.avatar || S.user.name?.split(' ').map(w=>w[0]).join('').slice(0,2) || '?';
  const role  = ROLE_LABELS[S.user.role] || S.user.role;
  const color = ROLE_COLORS[S.user.role] || '#8a87a0';

  const sav  = document.getElementById('sidebar-user-avatar');
  const snm  = document.getElementById('sidebar-user-name');
  const srl  = document.getElementById('sidebar-user-role');
  const tav  = document.getElementById('topbar-user-avatar');
  const tnm  = document.getElementById('topbar-user-name');
  const trb  = document.getElementById('topbar-role-badge');

  if (sav) { sav.textContent = av; sav.style.background = color + '33'; sav.style.color = color; }
  if (snm) snm.textContent = S.user.name;
  if (srl) { srl.textContent = role; srl.style.color = color; }
  if (tav) { tav.textContent = av; tav.style.background = color + '22'; tav.style.color = color; }
  if (tnm) tnm.textContent = S.user.name;
  if (trb) { trb.textContent = role; trb.style.background = color + '22'; trb.style.color = color; }
}

/* ═══════════════════════════════════════════════════════════════════════════
   DATA LOADING
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadProjects() {
  try {
    S.projects = await GET('/projects');
  } catch(e) {
    S.projects = [];
  }
}
async function loadIAMUsers() {
  try { S.iamUsers = await GET('/users'); } catch(_) { S.iamUsers = []; }
}
async function loadAuditLog() {
  try { S.auditLog = await GET('/audit?limit=200'); } catch(_) { S.auditLog = []; }
}
async function loadJobEntries(month) {
  try { S.jobEntries = await GET(`/job-entries?month=${month}`); } catch(_) { S.jobEntries = []; }
}
function completedTasksForMonth(month) {
  const rows = [];
  S.projects.forEach(p => {
    (p.tasks || []).forEach(t => {
      if (t.status !== 'done') return;
      const completedAt = t.completedAt || t.updatedAt || t.dueDate || t.createdAt;
      if (!completedAt || String(completedAt).slice(0, 7) !== month) return;
      rows.push({ date: completedAt, project: p.name, name: t.name });
    });
  });
  return rows.sort((a, b) => new Date(a.date) - new Date(b.date));
}

/* ═══════════════════════════════════════════════════════════════════════════
   RENDER
   ═══════════════════════════════════════════════════════════════════════════ */
function setView(view) {
  S.view = view;
  document.querySelectorAll('.nav-item[data-view]').forEach(b => {
    b.classList.toggle('active', b.dataset.view === view);
  });
  const titles = {
    dashboard:'Dashboard', projects:'Projects', timeline:'Timeline',
    analytics:'Analytics', issues:'Issues', cicd:'CI / CD',
    'project-detail': getProject()?.name || 'Project',
    iam:'Identity & Access', audit:'Audit Log', jobcard:'Job Card'
  };
  const pt = document.getElementById('page-title');
  if (pt) pt.textContent = titles[view] || view;

  const ta = document.getElementById('topbar-action');
  if (ta) {
    ta.style.display = (view === 'projects' || view === 'dashboard') && can('projects:create') ? '' : 'none';
  }
  renderContent();
  updateNav();
}

function renderAll() {
  renderSidebar();
  renderContent();
  updateNav();
}

function renderSidebar() {
  const container = document.getElementById('sidebar-projects');
  if (!container) return;
  if (!S.projects.length) {
    container.innerHTML = `<div style="padding:8px 16px;color:var(--txt3);font-size:12px">No projects yet</div>`;
  } else {
    container.innerHTML = S.projects.map(p => `
      <button class="sidebar-proj-item ${S.selectedProjectId===p.id?'active':''}"
        data-action="goto-project" data-id="${p.id}">
        <span class="sidebar-proj-dot" style="background:${p.color}"></span>
        <span class="sidebar-proj-name">${esc(p.name)}</span>
        <span class="sidebar-proj-badge ${PROJ_STATUS[p.status]?.css||''}">${PROJ_STATUS[p.status]?.label||p.status}</span>
      </button>`).join('');
  }

  const overdue = allOverdue();
  const overdueEl = document.getElementById('sidebar-overdue');
  const overdueBadge = document.getElementById('overdue-badge');
  const overdueCount = document.getElementById('overdue-count');
  if (overdue.length) {
    if (overdueEl) {
      overdueEl.style.display = '';
      overdueEl.innerHTML = `
        <div class="sidebar-section-label" style="color:var(--danger)">OVERDUE (${overdue.length})</div>
        ${overdue.slice(0,3).map(t=>`
          <div class="sidebar-overdue-item" data-action="goto-project" data-id="${t.projectId}">
            <span style="background:${t.projectColor}" class="sidebar-proj-dot"></span>
            <span style="font-size:11px;color:var(--txt2)">${esc(t.name)}</span>
          </div>`).join('')}`;
    }
    if (overdueBadge) overdueBadge.style.display = '';
    if (overdueCount) overdueCount.textContent = `${overdue.length} overdue`;
  } else {
    if (overdueEl) overdueEl.style.display = 'none';
    if (overdueBadge) overdueBadge.style.display = 'none';
  }
}

function updateNav() {}

function renderContent() {
  const content = document.getElementById('content');
  if (!content) return;
  destroyCharts();
  switch(S.view) {
    case 'dashboard':      content.innerHTML = renderDashboard();    break;
    case 'projects':       content.innerHTML = renderProjects();      break;
    case 'project-detail': content.innerHTML = renderProjectDetail(); break;
    case 'timeline':       content.innerHTML = renderTimeline();      break;
    case 'analytics':      content.innerHTML = renderAnalytics();     break;
    case 'issues':         content.innerHTML = renderIssues();        break;
    case 'cicd':           content.innerHTML = renderCICD();          break;
    case 'jobcard':        content.innerHTML = renderJobCard();       break;
    case 'iam':            content.innerHTML = renderIAM();           break;
    case 'audit':          content.innerHTML = renderAuditLog();      break;
    default: content.innerHTML = '<div class="empty-state">View not found</div>';
  }
  if (S.view === 'analytics') initCharts();
  if (S.view === 'timeline')  initTimelineCharts();
  bindContentEvents();
}

/* ─── Dashboard ──────────────────────────────────────────────────────────────── */
function renderDashboard() {
  const projects = S.projects;
  const overdue = allOverdue();
  const allTasks = projects.flatMap(p=>p.tasks);
  const done = allTasks.filter(t=>t.status==='done').length;
  const inProg = allTasks.filter(t=>t.status==='in-progress').length;
  const totalIssues = allTasks.flatMap(t=>t.issues).filter(i=>!i.resolved).length;
  const avgProgress = projects.length ? Math.round(projects.reduce((s,p)=>s+projProgress(p),0)/projects.length) : 0;

  if (!projects.length) {
    return `
      <div class="dashboard-empty">
        <div class="empty-icon">◫</div>
        <h2 class="empty-title">No Projects Yet</h2>
        <p class="empty-desc">Create your first project to get started with the Command Center.</p>
        ${can('projects:create') ? `<button class="btn-primary" data-action="new-project">+ Create Project</button>` : ''}
      </div>`;
  }

  return `
    <div class="dashboard-grid">
      <div class="stat-card"><div class="stat-label">Total Projects</div>
        <div class="stat-value">${projects.length}</div>
        <div class="stat-sub">${projects.filter(p=>p.status==='active').length} active</div></div>
      <div class="stat-card"><div class="stat-label">Tasks Complete</div>
        <div class="stat-value">${done}</div>
        <div class="stat-sub">of ${allTasks.length} total</div></div>
      <div class="stat-card"><div class="stat-label">In Progress</div>
        <div class="stat-value">${inProg}</div>
        <div class="stat-sub">active tasks</div></div>
      <div class="stat-card" style="--accent:var(--danger)"><div class="stat-label">Open Issues</div>
        <div class="stat-value" style="color:${totalIssues?'var(--danger)':'var(--success)'}">${totalIssues}</div>
        <div class="stat-sub">${totalIssues?'needs attention':'all clear'}</div></div>
    </div>

    ${overdue.length ? `
      <div class="section-header"><h2 class="section-title" style="color:var(--danger)">⚠ Overdue Tasks</h2></div>
      <div class="tasks-list">
        ${overdue.slice(0,5).map(t=>`
          <div class="task-row overdue-row" data-action="goto-project" data-id="${t.projectId}">
            <span style="background:${t.projectColor};width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0"></span>
            <div style="flex:1"><div class="task-name">${esc(t.name)}</div>
              <div class="task-meta"><span>${esc(t.projectName)}</span> · Due ${fmtDate(t.dueDate)}</div></div>
            <span class="priority-badge" style="color:${PRIORITY[t.priority]?.color||'#fff'}">${PRIORITY[t.priority]?.label||t.priority}</span>
          </div>`).join('')}
      </div>` : ''}

    <div class="section-header" style="margin-top:${overdue.length?'32px':'0'}">
      <h2 class="section-title">Projects</h2>
      ${can('projects:create') ? `<button class="btn-secondary" data-action="new-project">+ New</button>` : ''}
    </div>
    <div class="projects-grid">
      ${projects.map(p => {
        const prog = projProgress(p);
        const openIssues = p.tasks.flatMap(t=>t.issues).filter(i=>!i.resolved).length;
        return `
          <div class="project-card" data-action="goto-project" data-id="${p.id}">
            <div class="project-card-header">
              <div class="project-color-dot" style="background:${p.color}"></div>
              <div class="project-info">
                <div class="project-name">${esc(p.name)}</div>
                <div class="project-desc">${esc(p.description||'')}</div>
              </div>
              <span class="status-badge ${PROJ_STATUS[p.status]?.css||''}">${PROJ_STATUS[p.status]?.label||p.status}</span>
            </div>
            <div class="progress-bar-wrap">
              <div class="progress-bar-track"><div class="progress-bar-fill" style="width:${prog}%;background:${p.color}"></div></div>
              <span class="progress-label">${prog}%</span>
            </div>
            <div class="project-card-footer">
              <span class="meta-chip">◫ ${p.tasks.length} tasks</span>
              <span class="meta-chip">✓ ${p.tasks.filter(t=>t.status==='done').length} done</span>
              ${openIssues ? `<span class="meta-chip danger-chip">⚠ ${openIssues} issues</span>` : ''}
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

/* ─── Projects List ──────────────────────────────────────────────────────────── */
function renderProjects() {
  return `
    <div class="section-header">
      <h2 class="section-title">All Projects</h2>
      ${can('projects:create') ? `<button class="btn-primary" data-action="new-project">+ New Project</button>` : ''}
    </div>
    ${!S.projects.length ? `
      <div class="empty-state">
        <div class="empty-icon">◫</div>
        <p>No projects yet. ${can('projects:create') ? 'Create one to get started.' : 'Ask a manager to create one.'}</p>
        ${can('projects:create') ? `<button class="btn-primary" style="margin-top:16px" data-action="new-project">+ New Project</button>` : ''}
      </div>` :
    `<div class="projects-table">
      <div class="table-header-row">
        <div>Project</div><div>Status</div><div>Progress</div><div>Tasks</div><div>Issues</div><div>Created</div>
        ${can('projects:delete') || can('projects:update') ? '<div>Actions</div>' : ''}
      </div>
      ${S.projects.map(p => {
        const prog = projProgress(p);
        const openIssues = p.tasks.flatMap(t=>t.issues).filter(i=>!i.resolved).length;
        return `
          <div class="table-row" data-action="goto-project" data-id="${p.id}">
            <div class="table-proj-cell">
              <span class="table-proj-dot" style="background:${p.color}"></span>
              <div class="table-proj-info">
                <div class="table-proj-name">${esc(p.name)}</div>
                <div class="table-proj-desc">${esc(p.description||'')}</div>
              </div>
            </div>
            <div><span class="status-badge ${PROJ_STATUS[p.status]?.css||''}">${PROJ_STATUS[p.status]?.label||p.status}</span></div>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="flex:1;height:6px;background:var(--border);border-radius:99px;min-width:80px">
                <div style="height:100%;width:${prog}%;background:${p.color};border-radius:99px"></div>
              </div>
              <span style="font-size:12px;color:var(--txt2)">${prog}%</span>
            </div>
            <div style="color:var(--txt2)">${p.tasks.length}</div>
            <div style="color:${openIssues?'var(--danger)':'var(--txt3)'};font-weight:${openIssues?'700':'400'}">${openIssues||'—'}</div>
            <div style="color:var(--txt2);font-size:12px">${fmtDate(p.createdAt)}</div>
            ${can('projects:delete') || can('projects:update') ? `
              <div style="display:flex;gap:8px" onclick="event.stopPropagation()">
                ${can('projects:update') ? `<button class="action-btn" data-action="edit-project" data-id="${p.id}">Edit</button>` : ''}
                ${can('projects:delete') ? `<button class="action-btn danger" data-action="delete-project" data-id="${p.id}">Delete</button>` : ''}
              </div>` : ''}
          </div>`;
      }).join('')}
    </div>`}`;
}

/* ─── Project Detail ─────────────────────────────────────────────────────────── */
function renderProjectDetail() {
  const p = getProject();
  if (!p) return '<div class="empty-state">Project not found</div>';
  const filtered = S.filterStatus === 'all' ? p.tasks : p.tasks.filter(t=>t.status===S.filterStatus);
  const prog = projProgress(p);
  const openIssues = p.tasks.flatMap(t=>t.issues).filter(i=>!i.resolved).length;

  return `
    <div class="project-detail-header">
      <div style="display:flex;align-items:center;gap:12px">
        <div style="width:16px;height:16px;border-radius:50%;background:${p.color}"></div>
        <div>
          <h2 style="font-size:22px">${esc(p.name)}</h2>
          ${p.description ? `<p style="color:var(--txt2);margin-top:2px">${esc(p.description)}</p>` : ''}
        </div>
        <span class="status-badge ${PROJ_STATUS[p.status]?.css||''}" style="margin-left:4px">${PROJ_STATUS[p.status]?.label||p.status}</span>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${can('projects:update') ? `<button class="btn-secondary" data-action="edit-project" data-id="${p.id}">Edit Project</button>` : ''}
        ${can('projects:delete') ? `<button class="btn-secondary danger" data-action="delete-project" data-id="${p.id}">Delete</button>` : ''}
        ${can('tasks:create') ? `<button class="btn-primary" data-action="new-task">+ Add Task</button>` : ''}
      </div>
    </div>
    <div class="dashboard-grid" style="margin-bottom:24px">
      <div class="stat-card"><div class="stat-label">Progress</div><div class="stat-value">${prog}%</div></div>
      <div class="stat-card"><div class="stat-label">Tasks</div><div class="stat-value">${p.tasks.length}</div>
        <div class="stat-sub">${p.tasks.filter(t=>t.status==='done').length} done</div></div>
      <div class="stat-card"><div class="stat-label">Open Issues</div>
        <div class="stat-value" style="color:${openIssues?'var(--danger)':'var(--success)'}">${openIssues}</div></div>
      <div class="stat-card"><div class="stat-label">Created</div>
        <div style="font-size:13px;color:var(--txt2);margin-top:4px">${fmtDate(p.createdAt)}</div>
        ${p.createdByName ? `<div class="stat-sub">by ${esc(p.createdByName)}</div>` : ''}</div>
    </div>
    <div class="section-header">
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${['all','todo','in-progress','done','blocked'].map(s=>`
          <button class="filter-chip ${S.filterStatus===s?'active':''}" data-action="filter" data-status="${s}">
            ${s==='all'?'All':STATUS[s]?.label||s}
          </button>`).join('')}
      </div>
    </div>
    <div class="tasks-list">
      ${!filtered.length ? `<div class="empty-state" style="padding:40px 0">No tasks matching this filter</div>` :
        filtered.map(t => {
          const st = STATUS[t.status]||STATUS.todo;
          const pr = PRIORITY[t.priority]||PRIORITY.medium;
          const overdue = isOverdue(t);
          const issues = t.issues.filter(i=>!i.resolved).length;
          return `
            <div class="task-row ${overdue?'overdue-row':''}" data-action="task-detail" data-task-id="${t.id}">
              <span style="color:${st.color};font-size:18px;flex-shrink:0">${st.icon}</span>
              <div style="flex:1">
                <div class="task-name ${t.status==='done'?'done':''}">${esc(t.name)}</div>
                <div class="task-meta">
                  <span style="color:${pr.color}">${pr.label}</span>
                  ${t.assignee?`· <span>${esc(t.assignee)}</span>`:''}
                  ${t.status==='done' && t.completedAt
                    ? `· <span style="color:var(--success)">Completed ${fmtDate(t.completedAt)}</span>`
                    : t.dueDate ? `· <span style="color:${overdue?'var(--danger)':'var(--txt2)'}">Due ${fmtDate(t.dueDate)}</span>` : ''
                  }
                  ${issues?`· <span style="color:var(--danger)">⚠ ${issues} issue${issues>1?'s':''}</span>`:''}
                </div>
                ${t.tags?.length?`<div style="display:flex;gap:4px;margin-top:4px;flex-wrap:wrap">${t.tags.map(g=>`<span class="tag">${esc(g)}</span>`).join('')}</div>`:''}
              </div>
              <div style="text-align:right;flex-shrink:0">
                <div style="font-size:13px;color:var(--txt2)">${t.progress}%</div>
                <div class="task-progress-mini">
                  <div style="width:${t.progress}%;background:${p.color}"></div>
                </div>
              </div>
            </div>`; }).join('')}
    </div>`;
}

/* ─── Timeline ───────────────────────────────────────────────────────────────── */

function renderTimeline() {
  const tasks = S.projects.flatMap(p=>p.tasks.map(t=>({...t,projectId:p.id,projectName:p.name,projectColor:p.color})))
    .filter(t=>t.startDate&&t.dueDate);
  if (!tasks.length) return '<div class="empty-state"><div class="empty-icon">▤</div><p>No tasks with dates set yet.</p></div>';

  const today = d2date(new Date());
  const DAY_W = 34; // px per day — tweak for zoom

  // ── Date range: 3 days padding either side ──
  let rangeStart = d2date(tasks.reduce((m,t)=>t.startDate<m?t.startDate:m, tasks[0].startDate));
  let rangeEnd   = d2date(tasks.reduce((m,t)=>t.dueDate>m?t.dueDate:m, tasks[0].dueDate));
  rangeStart = new Date(rangeStart.getTime() - 3*DAY_MS);
  rangeEnd   = new Date(rangeEnd.getTime()   + 3*DAY_MS);
  const totalDays = daysBetween(rangeStart, rangeEnd) + 1;
  const totalWidth = totalDays * DAY_W;

  // ── Month bands ──
  const months = [];
  let cursor = new Date(rangeStart);
  while (cursor <= rangeEnd) {
    const monthStart = new Date(cursor);
    const nextMonth = new Date(cursor.getFullYear(), cursor.getMonth()+1, 1);
    const bandEnd = nextMonth < rangeEnd ? new Date(nextMonth.getTime()-DAY_MS) : rangeEnd;
    months.push({
      label: monthStart.toLocaleDateString(undefined,{month:'long'}),
      left: daysBetween(rangeStart, monthStart) * DAY_W,
      width: (daysBetween(monthStart, bandEnd)+1) * DAY_W
    });
    cursor = nextMonth;
  }

  // ── Day ticks (every 3 days) ──
  const ticks = [];
  for (let i=0;i<totalDays;i+=3) {
    const dt = new Date(rangeStart.getTime() + i*DAY_MS);
    ticks.push({ left: i*DAY_W, label: dt.getDate(), isToday: daysBetween(rangeStart,today)===i });
  }

  // ── Swimlanes: one per project ──
  const lanes = S.projects.filter(p => tasks.some(t=>t.projectId===p.id));

  const todayLeft = daysBetween(rangeStart, today) * DAY_W;

  // ── Upcoming panel: not done, sorted by due date ──
  const upcoming = tasks.filter(t=>t.status!=='done').sort((a,b)=>new Date(a.dueDate)-new Date(b.dueDate)).slice(0,8);

  return `
    <div class="section-header"><h2 class="section-title">Event Calendar</h2></div>

    <div class="gantt-layout">
      <div class="gantt-scroll">
        <div class="gantt-inner" style="width:${totalWidth}px">

          <div class="gantt-month-row">
            ${months.map(m=>`<div class="gantt-month" style="left:${m.left}px;width:${m.width}px">${m.label}</div>`).join('')}
          </div>

          <div class="gantt-tick-row">
            ${ticks.map(tk=>`<div class="gantt-tick ${tk.isToday?'is-today':''}" style="left:${tk.left}px">${tk.label}</div>`).join('')}
          </div>

          <div class="gantt-body" style="width:${totalWidth}px">
            <div class="gantt-today-line" style="left:${todayLeft}px"></div>
            ${lanes.map(p=>{
              const laneTasks = tasks.filter(t=>t.projectId===p.id);
              return `
              <div class="gantt-row">
                <div class="gantt-row-track" style="width:${totalWidth}px">
                  ${laneTasks.map(t=>{
                    const left  = daysBetween(rangeStart, t.startDate) * DAY_W;
                    const width = Math.max((daysBetween(t.startDate, t.dueDate)+1) * DAY_W - 6, DAY_W - 6);
                    const overdue = isOverdue(t);
                    const st = STATUS[t.status]||STATUS.todo;
                    return `
                    <div class="gantt-bar ${overdue?'is-overdue':''}"
                         style="left:${left}px;width:${width}px;background:${p.color}22;border-color:${p.color}66"
                         data-action="task-detail" data-task-id="${t.id}" title="${esc(t.name)}">
                      <div class="gantt-bar-fill" style="width:${t.progress}%;background:${p.color}"></div>
                      <span class="gantt-bar-label">${esc(t.name)}</span>
                      <span class="gantt-bar-status" style="color:${st.color}">${st.icon}</span>
                    </div>`;
                  }).join('')}
                </div>
              </div>`;
            }).join('')}
          </div>
        </div>
      </div>

      <div class="gantt-lane-labels">
        <div class="gantt-lane-labels-spacer"></div>
        ${lanes.map(p=>`
          <div class="gantt-lane-label">
            <span class="gantt-lane-dot" style="background:${p.color}"></span>
            ${esc(p.name)}
          </div>`).join('')}
      </div>
    </div>

    <div class="upcoming-panel">
      <h3 class="upcoming-title">Upcoming</h3>
      ${!upcoming.length ? `<div class="empty-state" style="padding:24px 0">Nothing upcoming 🎉</div>` :
        upcoming.map(t=>{
          const overdue = isOverdue(t);
          const left = daysLeft(t.dueDate);
          const st = STATUS[t.status]||STATUS.todo;
          return `
          <div class="upcoming-item" data-action="task-detail" data-task-id="${t.id}">
            <span class="upcoming-dot" style="background:${t.projectColor}"></span>
            <div class="upcoming-body">
              <div class="upcoming-name">${esc(t.name)}</div>
              <div class="upcoming-meta">
                <span style="color:${t.projectColor}">${esc(t.projectName)}</span>
                · Due ${fmtDate(t.dueDate)}
                ${overdue?`<span style="color:var(--danger);font-weight:700"> · OVERDUE</span>`:`<span style="color:var(--txt3)"> · ${left}d left</span>`}
              </div>
            </div>
            <div class="upcoming-progress">
              <div class="upcoming-progress-track"><div style="width:${t.progress}%;background:${t.projectColor}"></div></div>
              <span>${t.progress}%</span>
            </div>
            <span class="status-badge" style="background:${st.color}22;color:${st.color}">${st.label}</span>
          </div>`;
        }).join('')}
    </div>
    ${renderCommitCalendarSection()}
    ${renderEventsVsCommitsSection()}`;
}

function renderCommitCalendarSection() {
  const cal = S.commitCalendar;
  const monthPicker = `
    <select class="form-input commit-cal-month" id="commit-cal-month" style="width:auto;font-size:12px;padding:5px 10px">
      ${commitCalMonthOptions().map(o=>`<option value="${o.value}" ${o.value===S.commitCalMonth?'selected':''}>${o.label}</option>`).join('')}
    </select>`;

  if (!cal) return `
    <div class="upcoming-panel" style="margin-top:24px">
      <div class="section-header" style="margin-bottom:10px"><h3 class="upcoming-title" style="margin:0">Commit Calendar</h3>${monthPicker}</div>
      <div class="empty-state" style="padding:24px 0">Loading commit activity…</div>
    </div>`;
  if (cal.error) return `
    <div class="upcoming-panel" style="margin-top:24px">
      <div class="section-header" style="margin-bottom:10px"><h3 class="upcoming-title" style="margin:0">Commit Calendar</h3>${monthPicker}</div>
      <div class="empty-state" style="padding:24px 0;color:var(--danger)">⚠ ${esc(cal.error)}</div>
    </div>`;

  const weeks = buildCommitCalendarWeeks(cal.byDate, cal.since, cal.until);
  const dayLabels = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const monthLabel = commitCalMonthOptions().find(o=>o.value===S.commitCalMonth)?.label || S.commitCalMonth;

  return `
    <div class="upcoming-panel" style="margin-top:24px">
      <div class="section-header" style="margin-bottom:10px;flex-wrap:wrap">
        <h3 class="upcoming-title" style="margin:0">Commit Calendar
          <span style="font-weight:400;color:var(--txt3);font-size:12px"> — ${cal.total} commit(s) across all connected repos, ${esc(monthLabel)}</span>
        </h3>
        ${monthPicker}
      </div>
      <div style="display:flex;gap:10px;overflow-x:auto;padding-bottom:6px">
        <div style="display:flex;flex-direction:column;gap:3px;padding-top:2px">
          ${dayLabels.map((d,i)=>`<span style="font-size:9px;color:var(--txt3);height:13px;line-height:13px">${i%2?d:''}</span>`).join('')}
        </div>
        <div style="display:flex;gap:3px">
          ${weeks.map(week=>`
            <div style="display:flex;flex-direction:column;gap:3px">
              ${week.map(day=>`
                <div title="${day.date}: ${day.count} commit(s)"
                     style="width:13px;height:13px;border-radius:3px;background:${commitColor(day.count)};opacity:${day.inRange?1:0.25}"></div>`).join('')}
            </div>`).join('')}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:10px;font-size:10px;color:var(--txt3)">
        Less
        ${[0,1,3,5,8].map(c=>`<div style="width:11px;height:11px;border-radius:3px;background:${commitColor(c)}"></div>`).join('')}
        More
      </div>
    </div>`;
}

function renderEventsVsCommitsSection() {
  return `
    <div class="upcoming-panel" style="margin-top:24px">
      <h3 class="upcoming-title">Events vs Commits</h3>
      <div class="chart-wrap" style="height:280px;width:100%">
        <canvas id="chart-events-vs-commits"></canvas>
      </div>
    </div>`;
}

/* ─── Analytics ──────────────────────────────────────────────────────────────── */
function renderAnalytics() {
  return `
    <div class="section-header"><h2 class="section-title">Analytics</h2></div>
    <div class="analytics-grid">
      <div class="chart-card"><div class="chart-title">Task Status Breakdown</div>
        <div class="chart-wrap"><canvas id="chart-status"></canvas></div></div>
      <div class="chart-card"><div class="chart-title">Project Progress</div>
        <div class="chart-wrap"><canvas id="chart-progress"></canvas></div></div>
      <div class="chart-card wide"><div class="chart-title">Priority Distribution</div>
        <div class="chart-wrap"><canvas id="chart-priority"></canvas></div></div>
    </div>`;
}

function destroyCharts() {
  Object.values(S.chartInstances).forEach(c => { try { c.destroy(); } catch(_){} });
  S.chartInstances = {};
}

function initCharts() {
  const isDark = S.theme === 'dark';
  const gridColor = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.06)';
  const textColor = isDark ? '#8a87a0' : '#5e5a78';
  const allTasks = S.projects.flatMap(p=>p.tasks);

  const statusCounts = Object.keys(STATUS).map(s=>({label:STATUS[s].label,count:allTasks.filter(t=>t.status===s).length,color:STATUS[s].color}));
  const ctxS = document.getElementById('chart-status')?.getContext('2d');
  if (ctxS && allTasks.length) {
    S.chartInstances.status = new Chart(ctxS,{type:'doughnut',data:{
      labels:statusCounts.map(s=>s.label),
      datasets:[{data:statusCounts.map(s=>s.count),backgroundColor:statusCounts.map(s=>s.color+'cc'),borderWidth:0}]
    },options:{plugins:{legend:{labels:{color:textColor}}},cutout:'65%'}});
  }

  const ctxP = document.getElementById('chart-progress')?.getContext('2d');
  if (ctxP && S.projects.length) {
    S.chartInstances.progress = new Chart(ctxP,{type:'bar',data:{
      labels:S.projects.map(p=>p.name.slice(0,16)+'…'),
      datasets:[{label:'Progress %',data:S.projects.map(projProgress),backgroundColor:S.projects.map(p=>p.color+'cc'),borderRadius:6,borderWidth:0}]
    },options:{scales:{y:{max:100,ticks:{color:textColor},grid:{color:gridColor}},x:{ticks:{color:textColor},grid:{color:'transparent'}}},plugins:{legend:{labels:{color:textColor}}}}});
  }

  const priorityCounts = Object.keys(PRIORITY).map(k=>({label:PRIORITY[k].label,count:allTasks.filter(t=>t.priority===k).length,color:PRIORITY[k].color}));
  const ctxPr = document.getElementById('chart-priority')?.getContext('2d');
  if (ctxPr && allTasks.length) {
    S.chartInstances.priority = new Chart(ctxPr,{type:'bar',data:{
      labels:priorityCounts.map(p=>p.label),
      datasets:[{label:'Tasks',data:priorityCounts.map(p=>p.count),backgroundColor:priorityCounts.map(p=>p.color+'cc'),borderRadius:6,borderWidth:0}]
    },options:{indexAxis:'y',scales:{x:{ticks:{color:textColor},grid:{color:gridColor}},y:{ticks:{color:textColor},grid:{color:'transparent'}}},plugins:{legend:{labels:{color:textColor}}}}});
  }
}

function initTimelineCharts() {
  const cal = S.commitCalendar;
  if (!cal || cal.error) return;

  const isDark = S.theme === 'dark';
  const gridColor = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.06)';
  const textColor = isDark ? '#8a87a0' : '#5e5a78';

  const start = d2date(cal.since);
  const end   = d2date(cal.until);
  const days = [];
  for (let d = new Date(start); d <= end; d = new Date(d.getTime() + DAY_MS)) days.push(d.toISOString().slice(0,10));

  const commitCounts = days.map(d => (cal.byDate[d] || []).length);
  const allTasks = S.projects.flatMap(p => p.tasks);
  const eventCounts = days.map(d => allTasks.filter(t => t.startDate === d || t.dueDate === d).length);

  const ctx = document.getElementById('chart-events-vs-commits')?.getContext('2d');
  if (!ctx) return;

  S.chartInstances.eventsVsCommits = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: days.map(d => d.slice(5)), // MM-DD
      datasets: [
        { label: 'Events',  data: eventCounts,  backgroundColor: '#5b6af0cc', borderRadius: 4, barPercentage: 0.95, categoryPercentage: 0.9 },
        { label: 'Commits', data: commitCounts, backgroundColor: '#22d3a4cc', borderRadius: 4, barPercentage: 0.95, categoryPercentage: 0.9 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,   // fill the full width of the container instead of a fixed aspect ratio
      scales: {
        x: { ticks: { color: textColor, maxTicksLimit: 14 }, grid: { color: 'transparent' } },
        y: { beginAtZero: true, ticks: { color: textColor, precision: 0 }, grid: { color: gridColor } }
      },
      plugins: { legend: { labels: { color: textColor } } }
    }
  });
}

/* ─── Issues ─────────────────────────────────────────────────────────────────── */
function renderIssues() {
  const allIssues = S.projects.flatMap(p=>p.tasks.flatMap(t=>t.issues.map(i=>({...i,taskName:t.name,taskId:t.id,projectName:p.name,projectId:p.id,projectColor:p.color}))));
  const open   = allIssues.filter(i=>!i.resolved);
  const closed = allIssues.filter(i=>i.resolved);
  const active = S.issuesTab==='open' ? open : closed;
  return `
    <div class="section-header">
      <h2 class="section-title">Issues</h2>
      <div style="display:flex;gap:6px">
        <button class="filter-chip ${S.issuesTab==='open'?'active':''}" data-action="issues-tab" data-tab="open">Open (${open.length})</button>
        <button class="filter-chip ${S.issuesTab==='closed'?'active':''}" data-action="issues-tab" data-tab="closed">Resolved (${closed.length})</button>
      </div>
    </div>
    ${!active.length ? `<div class="empty-state"><div class="empty-icon">⚠</div><p>${S.issuesTab==='open'?'No open issues — all clear!':'No resolved issues yet.'}</p></div>` :
    `<div class="issues-list">
      ${active.map(i=>{
        const sev = SEVERITY[i.severity]||SEVERITY.medium;
        return `<div class="issue-row">
          <div style="display:flex;align-items:center;gap:10px;flex:1">
            <span style="color:${sev.color};background:${sev.bg};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase">${i.severity}</span>
            <div>
              <div style="color:var(--txt);font-weight:500">${esc(i.text)}</div>
              <div style="font-size:11px;color:var(--txt2);margin-top:2px">
                <span style="color:${i.projectColor}">${esc(i.projectName)}</span>
                · ${esc(i.taskName)} · ${fmtDate(i.createdAt)}
              </div>
            </div>
          </div>
          <span class="status-badge ${i.resolved?'badge-success':'badge-danger'}">${i.resolved?'Resolved':'Open'}</span>
        </div>`;}).join('')}
    </div>`}`;
}

/* ─── CI/CD — GitHub Actions ─────────────────────────────────────────────────── */

const JOB_ICON   = { success:'✓', failing:'✕', running:'◑', queued:'○', skipped:'—' };
const JOB_COLOR  = { success:'var(--success)', failing:'var(--danger)', running:'var(--info)', queued:'var(--txt3)', skipped:'var(--txt3)' };
const DOT_CLASS  = { success:'success', failing:'failing', running:'running', pending:'pending' };
const STATUS_LABEL = { success:'Passed', failing:'Failed', running:'Running', pending:'Queued' };
const STATUS_COLOR = { success:'var(--success)', failing:'var(--danger)', running:'var(--info)', pending:'var(--warn)' };

S.githubCommits = {};
S.ghBranches    = {};
S.commitCalendar = null;
S.commitCalMonth = new Date().toISOString().slice(0, 7);

async function loadGithubCommits(projectId) {
  try {
    S.githubCommits[projectId] = await GET(`/projects/${projectId}/github/commits`);
  } catch (e) {
    S.githubCommits[projectId] = { error: e.message || 'Failed to load commits' };
  }
  if (S.view === 'cicd') renderContent();
}

async function loadCommitCalendar() {
  const [y, m] = S.commitCalMonth.split('-').map(Number);
  const since = new Date(Date.UTC(y, m - 1, 1));
  const until = new Date(Date.UTC(y, m, 0, 23, 59, 59)); // last day of the selected month
  try {
    S.commitCalendar = await GET(`/commits/calendar?since=${since.toISOString()}&until=${until.toISOString()}`);
  } catch (e) {
    S.commitCalendar = { error: e.message || 'Failed to load commit calendar' };
  }
  if (S.view === 'timeline') renderContent();
}

function commitCalMonthOptions() {
  const opts = [];
  const now = new Date();
  for (let i = 0; i < 12; i++) {
    const d = new Date(Date.UTC(now.getFullYear(), now.getMonth() - i, 1));
    const value = d.toISOString().slice(0, 7);
    const label = d.toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    opts.push({ value, label });
  }
  return opts;
}

function commitColor(count) {
  if (!count) return 'var(--bg3)';
  if (count >= 8) return '#22d3a4';
  if (count >= 5) return '#22d3a4cc';
  if (count >= 3) return '#22d3a499';
  return '#22d3a455';
}

function buildCommitCalendarWeeks(byDate, since, until) {
  const start = d2date(since);
  const end   = d2date(until);
  const gridStart = new Date(start.getTime() - start.getDay() * DAY_MS); // align to Sunday
  const totalDays = Math.round((end - gridStart) / DAY_MS) + 1;

  const weeks = [];
  let week = [];
  for (let i = 0; i < totalDays; i++) {
    const day = new Date(gridStart.getTime() + i * DAY_MS);
    const key = day.toISOString().slice(0, 10);
    week.push({ date: key, count: (byDate[key] || []).length, inRange: day >= start && day <= end });
    if (day.getDay() === 6) { weeks.push(week); week = []; }
  }
  if (week.length) weeks.push(week);
  return weeks;
}

function renderJobCard() {
  const month = S.jobCardMonth;
  const tasksDone = completedTasksForMonth(month);
  const custom = S.jobEntries.slice().sort((a,b) => (a.date||'').localeCompare(b.date||''));
  const connectedRepos = S.projects.filter(p => p.github);
  const src = S.jobCardSources;

  return `
    <div class="section-header" style="margin-bottom:18px">
      <div>
        <h2 class="section-title">Job Card</h2>
        <div style="font-size:12px;color:var(--txt2);margin-top:3px">Commits + completed tasks + custom entries, combined per month</div>
      </div>
    </div>

    <div class="jobcard-bar" style="flex-wrap:wrap;gap:12px">
      <span style="font-size:13px;color:var(--txt2)">Month:</span>
      <input class="form-input jobcard-page-month" type="month" id="jobcard-page-month" style="width:160px" value="${esc(month)}" />

      <label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--txt2)">
        <input type="checkbox" class="jobcard-source-toggle" data-source="commits" ${src.commits?'checked':''}> Commits
      </label>
      <label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--txt2)">
        <input type="checkbox" class="jobcard-source-toggle" data-source="tasks" ${src.tasks?'checked':''}> Completed Tasks
      </label>
      <label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--txt2)">
        <input type="checkbox" class="jobcard-source-toggle" data-source="custom" ${src.custom?'checked':''}> Custom Entries
      </label>

      <button class="btn-primary" data-action="export-job-card">⬇ Export PDF</button>
      <button class="btn-secondary" data-action="export-job-card-csv">⬇ Export CSV</button>
      ${can('tasks:create') ? `<button class="btn-secondary" data-action="new-job-entry" style="margin-left:auto">+ Add Custom Job</button>` : ''}
    </div>

    <div style="font-size:11px;color:var(--txt3);margin:4px 0 20px">
      ${connectedRepos.length
        ? `Commits included from: ${connectedRepos.map(p=>esc(p.name)).join(', ')}`
        : `No GitHub repos connected — commits will be empty unless you connect one in CI / CD.`}
    </div>

    <div class="section-header" style="margin-bottom:10px">
      <h3 style="font-size:14px;color:var(--txt)">Custom Job Entries</h3>
    </div>
    <div class="audit-list" style="margin-bottom:24px">
      ${!custom.length ? '<div class="empty-state">No custom entries for this month yet.</div>' :
        custom.map(e => `
        <div class="audit-row">
          <span style="font-size:11px;color:var(--txt3);white-space:nowrap">${esc(e.date)}</span>
          <div style="flex:1">
            ${e.projectName ? `<span style="color:var(--info);font-size:12px">[${esc(e.projectName)}]</span> ` : ''}
            <span style="color:var(--txt2);font-size:12px">${esc(e.description)}</span>
          </div>
          ${can('tasks:update') ? `<button class="btn-secondary" data-action="edit-job-entry" data-id="${e.id}" style="padding:2px 8px;font-size:11px">Edit</button>` : ''}
          ${can('tasks:delete') ? `<button class="btn-secondary" data-action="delete-job-entry" data-id="${e.id}" style="padding:2px 8px;font-size:11px;color:var(--danger)">Delete</button>` : ''}
        </div>`).join('')}
    </div>

    <div class="section-header" style="margin-bottom:10px">
      <h3 style="font-size:14px;color:var(--txt)">Completed Tasks This Month</h3>
    </div>
    <div class="audit-list">
      ${!tasksDone.length ? '<div class="empty-state">No tasks completed this month.</div>' :
        tasksDone.map(t => `
        <div class="audit-row">
          <span style="font-size:11px;color:var(--txt3);white-space:nowrap">${fmtDate(t.date)}</span>
          <div style="flex:1">
            <span style="color:var(--info);font-size:12px">[${esc(t.project)}]</span>
            <span style="color:var(--txt2);font-size:12px">${esc(t.name)}</span>
          </div>
        </div>`).join('')}
    </div>`;
}

function renderCICD() {
  return `
    <div class="section-header" style="margin-bottom:18px">
      <div>
        <h2 class="section-title">CI / CD</h2>
        <div style="font-size:12px;color:var(--txt2);margin-top:3px">GitHub repositories & commit history</div>
      </div>
    </div>

    <div class="jobcard-bar">
      <span style="font-size:13px;color:var(--txt2)">Job card export now lives in its own section — commits, completed tasks, and custom entries all in one place.</span>
      <button class="btn-secondary" data-action="goto-jobcard">Open Job Card →</button>
    </div>

    <div class="cicd-list">
      ${S.projects.map(p => {
        const gh = p.github;
        const commits = S.githubCommits[p.id];
        const branchCache = S.ghBranches[p.id];
        return `
        <div class="gh-pipeline-card">
          <div class="gh-pipeline-header">
            <div class="gh-pipeline-status-dot ${gh ? 'success' : 'pending'}"></div>
            <div class="gh-pipeline-name">${esc(p.name)}</div>
            ${gh ? `
              <span style="font-size:11px;color:var(--txt3);font-family:'DM Mono',monospace">${esc(gh.owner)}/${esc(gh.repo)}</span>
              <select class="form-input gh-branch-switch" id="gh-branch-switch-${p.id}" data-project-id="${p.id}"
                style="font-size:11px;padding:3px 24px 3px 8px;width:auto;height:auto">
                ${(branchCache?.branches?.length ? branchCache.branches : [gh.branch]).map(b=>`
                  <option value="${esc(b)}" ${b===gh.branch?'selected':''}>⎇ ${esc(b)}</option>`).join('')}
              </select>
              <button class="action-btn" data-action="cicd-load-branches" data-project-id="${p.id}"
                style="font-size:11px;padding:3px 8px" title="Refresh branch list from GitHub">⟳</button>` : ''}
            <div style="margin-left:auto;display:flex;gap:8px">
              ${gh
                ? `<a href="https://github.com/${esc(gh.owner)}/${esc(gh.repo)}/tree/${esc(gh.branch)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent)">View repo →</a>
                   <button class="action-btn" data-action="cicd-disconnect" data-project-id="${p.id}" style="font-size:11px;padding:3px 10px">Disconnect</button>`
                : ''}
            </div>
          </div>

          ${!gh ? `
          <div class="cicd-connect-form" style="padding:14px;flex-direction:column;align-items:stretch">
            <input class="form-input" id="gh-repo-input-${p.id}" type="text"
              placeholder="https://github.com/org/repo  or  owner/repo" style="font-family:'DM Mono',monospace;font-size:12px"
              value="${esc(branchCache?.repoUrl||'')}" />
            <input class="form-input" id="gh-token-input-${p.id}" type="password"
              placeholder="Personal access token (optional, for private repos)" style="font-family:'DM Mono',monospace;font-size:12px"
              value="${esc(branchCache?.token||'')}" />
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <button class="btn-secondary" data-action="cicd-fetch-branches" data-project-id="${p.id}" style="flex-shrink:0">⟳ Fetch Branches</button>
              ${branchCache?.branches?.length ? `
                <select class="form-input" id="gh-branch-select-${p.id}" style="flex:1;min-width:140px">
                  ${branchCache.branches.map(b=>`
                    <option value="${esc(b)}" ${b===branchCache.defaultBranch?'selected':''}>${esc(b)}${b===branchCache.defaultBranch?' (default)':''}</option>`).join('')}
                </select>` : `<span style="font-size:12px;color:var(--txt3)">Fetch branches before connecting — repos don't always default to "main"</span>`}
            </div>
            <button class="btn-primary" data-action="cicd-connect" data-project-id="${p.id}">Connect</button>
          </div>` : `
          <div class="gh-jobs-list">
            ${!commits ? `<div style="padding:14px;color:var(--txt3);font-size:12px">Loading commits…</div>`
              : commits.error ? `
                <div style="padding:14px;color:var(--danger);font-size:12px">
                  ⚠ ${esc(commits.error)}
                  <div style="margin-top:8px;color:var(--txt2)">
                    This usually means <strong>${esc(gh.branch)}</strong> isn't a real branch on this repo.
                    Click <strong>⟳</strong> above to load the actual branches, then pick the correct one from the dropdown.
                  </div>
                </div>`
              : !commits.length ? `<div style="padding:14px;color:var(--txt3);font-size:12px">No commits found.</div>`
              : commits.slice(0,8).map(c => `
                <div class="gh-commit-row">
                  <span class="gh-commit-hash">${esc(c.sha)}</span>
                  <span class="gh-commit-msg">${esc(c.summary || c.message)}</span>
                  <span class="gh-commit-author" style="color:var(--txt3)">${esc(c.author)}</span>
                  <span style="font-size:11px;color:var(--txt3);margin-left:auto">${fmtDate(c.date)}</span>
                </div>`).join('')}
          </div>`}
        </div>`;
      }).join('')}
    </div>`;
}

/* ─── IAM View ───────────────────────────────────────────────────────────────── */
// Permission map used for the matrix table
const PERM_MAP = {
  superadmin:['projects:create','projects:update','projects:delete','tasks:create','tasks:update','tasks:delete','issues:create','issues:resolve','users:read','users:create','users:delete','audit:read','settings:manage'],
  admin:['projects:create','projects:update','projects:delete','tasks:create','tasks:update','tasks:delete','issues:create','issues:resolve','users:read','audit:read'],
  manager:['projects:create','projects:update','tasks:create','tasks:update','tasks:delete','issues:create','issues:resolve','users:read'],
  developer:['tasks:update','issues:create','issues:resolve'],
  viewer:[]
};

function renderIAM() {
  if (!can('users:read')) return '<div class="empty-state">Access denied</div>';
  const roleOrder = ['superadmin','admin','manager','developer','viewer'];
  const permList = ['projects:create','projects:update','projects:delete','tasks:create','tasks:update','tasks:delete','issues:create','issues:resolve','users:read','users:create','users:delete','audit:read','settings:manage'];

  return `
    <div class="section-header">
      <h2 class="section-title">Identity & Access Management</h2>
      ${can('users:create') ? `<button class="btn-primary" data-action="new-user">+ New User</button>` : ''}
    </div>
    <div class="iam-table">
      <div class="iam-header-row">
        <div>User</div><div>Role</div><div>Department</div><div>Status</div><div>Last Login</div>
        ${can('users:update') || can('users:delete') ? '<div>Actions</div>' : ''}
      </div>
      ${S.iamUsers.sort((a,b)=>roleOrder.indexOf(a.role)-roleOrder.indexOf(b.role)).map(u=>{
        const roleColor = ROLE_COLORS[u.role] || '#8a87a0';
        const roleLabel = ROLE_LABELS[u.role] || u.role;
        const isMe = u.id === S.user?.id;
        return `<div class="iam-row ${isMe?'iam-row-me':''}">
          <div class="iam-user-cell">
            <div class="iam-avatar" style="background:${roleColor}22;color:${roleColor}">${esc(u.avatar||'?')}</div>
            <div>
              <div class="iam-name">${esc(u.name)} ${isMe?'<span style="color:var(--accent);font-size:10px">(you)</span>':''}</div>
              <div class="iam-email">${esc(u.email)}</div>
              <div class="iam-username">@${esc(u.username)}</div>
            </div>
          </div>
          <div><span class="role-badge" style="background:${roleColor}18;color:${roleColor};border:1px solid ${roleColor}30">${roleLabel}</span></div>
          <div style="color:var(--txt2);font-size:13px">${esc(u.department||'—')}</div>
          <div><span class="status-badge ${u.active?'badge-success':'badge-danger'}">${u.active?'Active':'Inactive'}</span></div>
          <div style="color:var(--txt2);font-size:12px">${u.lastLogin?fmtDateTime(u.lastLogin):'Never'}</div>
          ${can('users:update') || can('users:delete') ? `
            <div style="display:flex;gap:6px">
              ${can('users:update') ? `<button class="action-btn" data-action="edit-user" data-id="${u.id}">Edit</button>` : ''}
              ${can('users:delete') && !isMe ? `<button class="action-btn danger" data-action="delete-user" data-id="${u.id}">Delete</button>` : ''}
            </div>` : ''}
        </div>`}).join('')}
    </div>
    <div class="section-header" style="margin-top:32px"><h2 class="section-title">Permissions Matrix</h2></div>
    <div class="perm-matrix">
      <div class="perm-matrix-header">
        <div>Permission</div>
        ${roleOrder.map(r=>`<div style="color:${ROLE_COLORS[r]}">${ROLE_LABELS[r]}</div>`).join('')}
      </div>
      ${permList.map(perm=>`
        <div class="perm-matrix-row">
          <div class="perm-name">${perm}</div>
          ${roleOrder.map(role=>{
            const has = (PERM_MAP[role]||[]).includes(perm);
            return `<div style="text-align:center;color:${has?'var(--success)':'var(--txt3)'}">${has?'✓':'—'}</div>`;
          }).join('')}
        </div>`).join('')}
    </div>`;
}

/* ─── Audit Log ──────────────────────────────────────────────────────────────── */
function renderAuditLog() {
  if (!can('audit:read')) return '<div class="empty-state">Access denied</div>';
  const actionColors = {
    LOGIN_SUCCESS:'var(--success)',LOGIN_FAIL:'var(--danger)',LOGOUT:'var(--txt2)',
    PROJECT_CREATED:'var(--info)',PROJECT_UPDATED:'var(--warn)',PROJECT_DELETED:'var(--danger)',
    TASK_CREATED:'var(--info)',TASK_UPDATED:'var(--warn)',TASK_DELETED:'var(--danger)',
    USER_CREATED:'var(--success)',USER_UPDATED:'var(--warn)',USER_DELETED:'var(--danger)',
    ACCOUNT_LOCKED:'var(--danger)',PASSWORD_CHANGED:'var(--warn)',SETTINGS_UPDATED:'var(--warn)',
    SYSTEM_INIT:'var(--txt3)'
  };
  return `
    <div class="section-header">
      <h2 class="section-title">Audit Log</h2>
      <span style="font-size:12px;color:var(--txt3)">Last ${S.auditLog.length} entries</span>
    </div>
    <div class="audit-list">
      ${!S.auditLog.length ? '<div class="empty-state">No audit entries</div>' :
        S.auditLog.map(e=>`<div class="audit-row">
          <span class="audit-action" style="color:${actionColors[e.action]||'var(--txt2)'}">${e.action}</span>
          <div style="flex:1">
            <span style="color:var(--txt);font-weight:500">${esc(e.userName)}</span>
            <span style="color:var(--txt3);margin:0 4px">·</span>
            <span style="color:var(--txt2);font-size:12px">${esc(e.details||'')}</span>
          </div>
          <span style="font-size:11px;color:var(--txt3);white-space:nowrap">${fmtDateTime(e.timestamp)}</span>
          <span style="font-size:10px;color:var(--txt3);font-family:monospace">${esc(e.ip||'')}</span>
        </div>`).join('')}
    </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   MODALS
   ═══════════════════════════════════════════════════════════════════════════ */
function openModal(html) {
  document.getElementById('modal-inner').innerHTML = html;
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  document.getElementById('modal-inner').innerHTML = '';
}

/* ─── New/Edit Project Modal ─────────────────────────────────────────────────── */
function openProjectModal(existing) {
  const isEdit = !!existing;
  const colorOpts = PROJ_COLORS.map(c=>`
    <label class="color-opt">
      <input type="radio" name="proj-color" value="${c}" ${(!existing&&c===PROJ_COLORS[0])||existing?.color===c?'checked':''}>
      <span style="background:${c}"></span>
    </label>`).join('');
  openModal(`
    <div class="modal-header">
      <h3>${isEdit?'Edit Project':'New Project'}</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <label class="form-label">Project Name *</label>
      <input class="form-input" id="np-name" type="text" value="${esc(existing?.name||'')}" placeholder="e.g. Website Redesign" />
      <label class="form-label">Description</label>
      <textarea class="form-input" id="np-desc" rows="2" placeholder="What's this project about?">${esc(existing?.description||'')}</textarea>
      <label class="form-label">Status</label>
      <select class="form-input" id="np-status">
        ${Object.entries(PROJ_STATUS).map(([v,l])=>`<option value="${v}" ${existing?.status===v?'selected':''}>${l.label}</option>`).join('')}
      </select>
      <label class="form-label">Color</label>
      <div class="color-picker">${colorOpts}</div>
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="np-save">${isEdit?'Save Changes':'Create Project'}</button>
    </div>`);

  document.getElementById('np-save')?.addEventListener('click', async () => {
    const name = document.getElementById('np-name')?.value.trim();
    if (!name) { toast('Project name required', 'danger'); return; }
    const body = {
      name,
      description: document.getElementById('np-desc')?.value.trim() || '',
      status: document.getElementById('np-status')?.value || 'active',
      color: document.querySelector('input[name="proj-color"]:checked')?.value || PROJ_COLORS[0]
    };
    try {
      if (isEdit) {
        const updated = await PUT(`/projects/${existing.id}`, body);
        const idx = S.projects.findIndex(p=>p.id===existing.id);
        if (idx>-1) S.projects[idx] = {...S.projects[idx], ...updated};
        toast('Project updated', 'success');
      } else {
        const created = await POST('/projects', body);
        S.projects.push(created);
        toast(`Project "${name}" created`, 'success');
      }
      closeModal();
      renderAll();
    } catch(e) {
      toast(e.message || 'Failed to save project', 'danger');
    }
  });
}

/* ─── Delete Project ─────────────────────────────────────────────────────────── */
function openDeleteProjectModal(projId) {
  const p = S.projects.find(x=>x.id===projId);
  if (!p) return;
  openModal(`
    <div class="modal-header">
      <h3 style="color:var(--danger)">Delete Project</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <p style="color:var(--txt2)">Are you sure you want to permanently delete <strong style="color:var(--txt)">${esc(p.name)}</strong>?</p>
      <p style="color:var(--danger);margin-top:12px;font-size:13px">This will also delete <strong>${p.tasks.length} task(s)</strong> and all associated issues. This action cannot be undone.</p>
      <label class="form-label" style="margin-top:16px">Type the project name to confirm:</label>
      <input class="form-input" id="del-confirm" type="text" placeholder="${esc(p.name)}" />
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="del-proj-btn" style="background:var(--danger)">Delete Permanently</button>
    </div>`);

  document.getElementById('del-proj-btn')?.addEventListener('click', async () => {
    const typed = document.getElementById('del-confirm')?.value.trim();
    if (typed !== p.name) { toast('Project name does not match', 'danger'); return; }
    try {
      await DELETE(`/projects/${p.id}`);
      S.projects = S.projects.filter(x=>x.id!==p.id);
      if (S.selectedProjectId === p.id) { S.selectedProjectId = null; S.view = 'projects'; }
      closeModal();
      renderAll();
      toast(`Project "${p.name}" deleted`, 'danger');
    } catch(e) {
      toast(e.message || 'Failed to delete project', 'danger');
    }
  });
}

function openJobEntryModal(existing) {
  const isEdit = !!existing;
  openModal(`
    <div class="modal-header">
      <h3>${isEdit ? 'Edit Job Entry' : 'Add Custom Job Entry'}</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <label class="form-label">Date *</label>
      <input class="form-input" id="je-date" type="date" value="${esc(existing?.date || S.jobCardMonth + '-01')}" />
      <label class="form-label">Project (optional)</label>
      <select class="form-input" id="je-project">
        <option value="">— No project —</option>
        ${S.projects.map(p => `<option value="${p.id}" ${existing?.projectId===p.id?'selected':''}>${esc(p.name)}</option>`).join('')}
      </select>
      <label class="form-label">Description *</label>
      <textarea class="form-input" id="je-desc" rows="3" placeholder="What work was done?">${esc(existing?.description||'')}</textarea>
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="je-save">${isEdit ? 'Save Changes' : 'Add Entry'}</button>
    </div>`);

  document.getElementById('je-save')?.addEventListener('click', async () => {
    const date = document.getElementById('je-date')?.value;
    const description = document.getElementById('je-desc')?.value.trim();
    const projectId = document.getElementById('je-project')?.value || '';
    if (!date) { toast('Date required', 'danger'); return; }
    if (!description) { toast('Description required', 'danger'); return; }
    const body = { date, description, projectId };
    try {
      if (isEdit) {
        const updated = await PUT(`/job-entries/${existing.id}`, body);
        const idx = S.jobEntries.findIndex(e => e.id === existing.id);
        if (idx > -1) S.jobEntries[idx] = updated;
        toast('Job entry updated', 'success');
      } else {
        const created = await POST('/job-entries', body);
        if ((created.date || '').startsWith(S.jobCardMonth)) S.jobEntries.push(created);
        toast('Job entry added', 'success');
      }
      closeModal();
      renderContent();
    } catch (e) {
      toast(e.message || 'Failed to save job entry', 'danger');
    }
  });
}

/* ─── New Task Modal ─────────────────────────────────────────────────────────── */
function openNewTaskModal() {
  const p = getProject();
  if (!p) return;
  openModal(`
    <div class="modal-header">
      <h3>New Task — ${esc(p.name)}</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <label class="form-label">Task Name *</label>
      <input class="form-input" id="nt-name" type="text" placeholder="e.g. Design system components" />
      <label class="form-label">Description</label>
      <textarea class="form-input" id="nt-desc" rows="2" placeholder="What needs to be done?"></textarea>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div>
          <label class="form-label">Status</label>
          <select class="form-input" id="nt-status">
            ${Object.entries(STATUS).map(([v,s])=>`<option value="${v}">${s.label}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="form-label">Priority</label>
          <select class="form-input" id="nt-priority">
            ${Object.entries(PRIORITY).map(([v,p])=>`<option value="${v}">${p.label}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="form-label">Start Date</label>
          <input class="form-input" id="nt-start" type="date" value="${today()}" />
        </div>
        <div>
          <label class="form-label">Due Date</label>
          <input class="form-input" id="nt-due" type="date" />
        </div>
      </div>
      <label class="form-label">Completed Date <span style="color:var(--txt3);font-weight:400">(leave blank unless already done)</span></label>
      <input class="form-input" id="nt-completed" type="date" />
      <label class="form-label">Progress (0%)</label>
      <input class="form-input" id="nt-progress" type="range" min="0" max="100" value="0" style="padding:0;height:32px" />
      <label class="form-label">Assignee</label>
      <input class="form-input" id="nt-assignee" type="text" placeholder="Team member name" />
      <label class="form-label">Tags (comma separated)</label>
      <input class="form-input" id="nt-tags" type="text" placeholder="frontend, design, api" />
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="nt-save">Add Task</button>
    </div>`);

  const progRange = document.getElementById('nt-progress');
  progRange?.addEventListener('input', () => {
    const lbl = document.querySelector('label[for]');
    document.querySelectorAll('.form-label').forEach(l => {
      if (l.textContent.startsWith('Progress')) l.textContent = `Progress (${progRange.value}%)`;
    });
  });

  document.getElementById('nt-save')?.addEventListener('click', async () => {
    const name = document.getElementById('nt-name')?.value.trim();
    if (!name) { toast('Task name required', 'danger'); return; }
    try {
      const body = {
        name,
        description: document.getElementById('nt-desc')?.value.trim() || '',
        status: document.getElementById('nt-status')?.value || 'todo',
        priority: document.getElementById('nt-priority')?.value || 'medium',
        startDate: document.getElementById('nt-start')?.value || today(),
        dueDate: document.getElementById('nt-due')?.value || '',
        progress: parseInt(document.getElementById('nt-progress')?.value || '0'),
        assignee: document.getElementById('nt-assignee')?.value.trim() || '',
        tags: document.getElementById('nt-tags')?.value.split(',').map(s=>s.trim()).filter(Boolean)
      };
      const completedVal = document.getElementById('nt-completed')?.value;
      if (completedVal) body.completedAt = completedVal;
      const task = await POST(`/projects/${p.id}/tasks`, body);
      const proj = getProject();
      if (proj) proj.tasks.push(task);
      closeModal();
      renderAll();
      toast(`Task "${name}" added`, 'success');
    } catch(e) {
      toast(e.message || 'Failed to add task', 'danger');
    }
  });
}

/* ─── Task Detail Modal ──────────────────────────────────────────────────────── */
function openTaskDetailModal(taskId) {
  const p = getProject();
  const t = p?.tasks.find(x=>x.id===taskId);
  if (!t) return;
  const openIssues = t.issues.filter(i=>!i.resolved);
  const doneIssues = t.issues.filter(i=>i.resolved);

  openModal(`
    <div class="modal-header">
      <h3>${esc(t.name)}</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <label class="form-label">Description</label>
      <textarea class="form-input" id="td-desc" rows="2" ${!can('tasks:update')?'readonly':''}>${esc(t.description||'')}</textarea>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div><label class="form-label">Status</label>
          <select class="form-input" id="td-status" ${!can('tasks:update')?'disabled':''}>
            ${Object.entries(STATUS).map(([v,s])=>`<option value="${v}" ${t.status===v?'selected':''}>${s.label}</option>`).join('')}
          </select></div>
        <div><label class="form-label">Priority</label>
          <select class="form-input" id="td-priority" ${!can('tasks:update')?'disabled':''}>
            ${Object.entries(PRIORITY).map(([v,pr])=>`<option value="${v}" ${t.priority===v?'selected':''}>${pr.label}</option>`).join('')}
          </select></div>
        <div><label class="form-label">Start</label>
          <input class="form-input" id="td-start" type="date" value="${t.startDate||''}" ${!can('tasks:update')?'readonly':''}></div>
            <div><label class="form-label">Due</label>
          <input class="form-input" id="td-due" type="date" value="${t.dueDate||''}" ${!can('tasks:update')?'readonly':''}></div>
      </div>
      <label class="form-label">Completed Date</label>
      <input class="form-input" id="td-completed" type="date" value="${t.completedAt ? String(t.completedAt).slice(0,10) : ''}" ${!can('tasks:update')?'readonly':''}/>
      <label class="form-label" id="td-prog-label">Progress (${t.progress}%)</label>
      <input class="form-input" id="td-progress" type="range" min="0" max="100" value="${t.progress}" style="padding:0;height:32px" ${!can('tasks:update')?'disabled':''}/>
      <label class="form-label">Assignee</label>
      <input class="form-input" id="td-assignee" type="text" value="${esc(t.assignee||'')}" ${!can('tasks:update')?'readonly':''}/>
      <label class="form-label">Tags</label>
      <input class="form-input" id="td-tags" type="text" value="${esc((t.tags||[]).join(', '))}" ${!can('tasks:update')?'readonly':''}/>

      <div class="modal-issues-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <h4 style="font-size:13px;font-weight:700">Issues (${openIssues.length} open)</h4>
          ${can('issues:create') ? `<button class="btn-secondary" id="td-add-issue-btn" style="font-size:12px;padding:4px 12px">+ Log Issue</button>` : ''}
        </div>
        <div id="td-issue-form" style="display:none;background:var(--modal2);padding:12px;border-radius:var(--radius-sm);margin-bottom:10px">
          <textarea class="form-input" id="td-issue-text" rows="2" placeholder="Describe the issue…"></textarea>
          <div style="display:flex;gap:8px;margin-top:8px">
            <select class="form-input" id="td-issue-sev" style="flex:1">
              ${['low','medium','high','critical'].map(s=>`<option value="${s}">${s.charAt(0).toUpperCase()+s.slice(1)}</option>`).join('')}
            </select>
            <button class="btn-primary" id="td-issue-save" style="flex-shrink:0">Save</button>
            <button class="btn-secondary" id="td-issue-cancel" style="flex-shrink:0">Cancel</button>
          </div>
        </div>
        <div id="td-issues-list">
          ${[...openIssues,...doneIssues].map(i=>{
            const sev = SEVERITY[i.severity]||SEVERITY.medium;
            return `<div class="modal-issue-row">
              ${can('issues:resolve') ? `<button class="resolve-check ${i.resolved?'checked':''}" data-resolve-issue data-issue-id="${i.id}">${i.resolved?'✓':''}</button>` : ''}
              <div style="flex:1">
                <div class="modal-issue-text ${i.resolved?'done':''}">${esc(i.text)}</div>
                <div class="modal-issue-meta">
                  <span style="color:${sev.color};font-weight:700;text-transform:uppercase;font-size:10px">${i.severity}</span>
                  <span>${fmtDate(i.createdAt)}</span>
                </div>
              </div>
            </div>`;}).join('')}
        </div>
      </div>
    </div>
    <div class="modal-footer">
      ${can('tasks:delete') ? `<button class="btn-secondary danger" id="td-delete">Delete Task</button>` : ''}
      <button class="btn-secondary" data-action="close-modal">Close</button>
      ${can('tasks:update') ? `<button class="btn-primary" id="td-save">Save Changes</button>` : ''}
    </div>`);

  // Progress slider
  const progRange = document.getElementById('td-progress');
  const progLabel = document.getElementById('td-prog-label');
  progRange?.addEventListener('input', () => { if(progLabel) progLabel.textContent = `Progress (${progRange.value}%)`; });

  // Issue form toggle
  document.getElementById('td-add-issue-btn')?.addEventListener('click', () => {
    const f = document.getElementById('td-issue-form');
    if (f) f.style.display = f.style.display==='none' ? 'block' : 'none';
  });
  document.getElementById('td-issue-cancel')?.addEventListener('click', () => {
    const f = document.getElementById('td-issue-form'); if(f) f.style.display='none';
  });

  document.getElementById('td-issue-save')?.addEventListener('click', async () => {
    const text = document.getElementById('td-issue-text')?.value.trim();
    if (!text) { toast('Issue description required', 'danger'); return; }
    try {
      const issue = await POST(`/projects/${p.id}/tasks/${t.id}/issues`, {
        text, severity: document.getElementById('td-issue-sev')?.value || 'medium'
      });
      t.issues.push(issue);
      const list = document.getElementById('td-issues-list');
      const sev = SEVERITY[issue.severity]||SEVERITY.medium;
      if (list) {
        list.insertAdjacentHTML('afterbegin', `
          <div class="modal-issue-row">
            ${can('issues:resolve') ? `<button class="resolve-check" data-resolve-issue data-issue-id="${issue.id}"></button>` : ''}
            <div style="flex:1">
              <div class="modal-issue-text">${esc(issue.text)}</div>
              <div class="modal-issue-meta">
                <span style="color:${sev.color};font-weight:700;text-transform:uppercase;font-size:10px">${issue.severity}</span>
                <span>${fmtDate(issue.createdAt)}</span>
              </div>
            </div>
          </div>`);
        bindResolveButtons(p, t);
      }
      document.getElementById('td-issue-text').value = '';
      document.getElementById('td-issue-form').style.display = 'none';
      renderSidebar();
      toast('Issue logged', 'info');
    } catch(e) {
      toast(e.message||'Failed to log issue', 'danger');
    }
  });

  bindResolveButtons(p, t);

    const initialCompleted = t.completedAt ? String(t.completedAt).slice(0,10) : '';

  document.getElementById('td-save')?.addEventListener('click', async () => {
    try {
      const body = {
        description: document.getElementById('td-desc')?.value.trim() || '',
        status:   document.getElementById('td-status')?.value || t.status,
        priority: document.getElementById('td-priority')?.value || t.priority,
        startDate: document.getElementById('td-start')?.value || t.startDate,
        dueDate:  document.getElementById('td-due')?.value || t.dueDate,
        assignee: document.getElementById('td-assignee')?.value.trim() || '',
        tags: document.getElementById('td-tags')?.value.split(',').map(s=>s.trim()).filter(Boolean),
        progress: parseInt(document.getElementById('td-progress')?.value || String(t.progress))
      };
      const completedNow = document.getElementById('td-completed')?.value || '';
      if (completedNow !== initialCompleted) body.completedAt = completedNow;

      const updated = await PUT(`/projects/${p.id}/tasks/${t.id}`, body);
      Object.assign(t, updated);
      closeModal();
      renderAll();
      toast('Task saved', 'success');
    } catch(e) {
      toast(e.message||'Failed to save task', 'danger');
    }
  });

  document.getElementById('td-delete')?.addEventListener('click', async () => {
    if (!confirm(`Delete task "${t.name}"?`)) return;
    try {
      await DELETE(`/projects/${p.id}/tasks/${t.id}`);
      const proj = getProject();
      if (proj) proj.tasks = proj.tasks.filter(x=>x.id!==t.id);
      closeModal();
      renderAll();
      toast('Task deleted', 'danger');
    } catch(e) {
      toast(e.message||'Failed to delete task', 'danger');
    }
  });
}

function bindResolveButtons(p, t) {
  document.querySelectorAll('[data-resolve-issue]').forEach(btn => {
    const clone = btn.cloneNode(true);
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', async () => {
      const issue = t.issues.find(i=>i.id===clone.dataset.issueId);
      if (!issue) return;
      try {
        const updated = await PUT(`/projects/${p.id}/tasks/${t.id}/issues/${issue.id}`, { resolved: !issue.resolved });
        issue.resolved = updated.resolved;
        clone.className = `resolve-check ${issue.resolved?'checked':''}`;
        clone.textContent = issue.resolved ? '✓' : '';
        const textEl = clone.parentElement?.querySelector('.modal-issue-text');
        if (textEl) textEl.className = `modal-issue-text ${issue.resolved?'done':''}`;
        renderSidebar();
        toast(issue.resolved?'Issue resolved':'Issue reopened', issue.resolved?'success':'info');
      } catch(e) {
        toast(e.message||'Failed to update issue', 'danger');
      }
    });
  });
}

/* ─── IAM Modals ─────────────────────────────────────────────────────────────── */
function openNewUserModal(existing) {
  const isEdit = !!existing;
  const roles = ['superadmin','admin','manager','developer','viewer'];
  openModal(`
    <div class="modal-header">
      <h3>${isEdit?'Edit User':'New User'}</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      ${!isEdit ? `
        <label class="form-label">Username *</label>
        <input class="form-input" id="nu-username" type="text" value="${esc(existing?.username||'')}" placeholder="username" />
        <label class="form-label">Email *</label>
        <input class="form-input" id="nu-email" type="email" value="${esc(existing?.email||'')}" placeholder="user@org.internal" />` : ''}
      <label class="form-label">Full Name *</label>
      <input class="form-input" id="nu-name" type="text" value="${esc(existing?.name||'')}" placeholder="Full Name" />
      <label class="form-label">Department</label>
      <input class="form-input" id="nu-dept" type="text" value="${esc(existing?.department||'')}" placeholder="Engineering" />
      <label class="form-label">Role *</label>
      <select class="form-input" id="nu-role">
        ${roles.map(r=>`<option value="${r}" ${existing?.role===r?'selected':''}>${ROLE_LABELS[r]}</option>`).join('')}
      </select>
      ${isEdit ? `
        <label class="form-label">Active</label>
        <select class="form-input" id="nu-active">
          <option value="true" ${existing?.active?'selected':''}>Active</option>
          <option value="false" ${!existing?.active?'selected':''}>Inactive</option>
        </select>` : `
        <label class="form-label">Password *</label>
        <input class="form-input" id="nu-password" type="password" placeholder="Minimum 8 characters" />`}
      ${isEdit && S.user?.role === 'superadmin' ? `
        <label class="form-label">Reset Password (leave blank to keep)</label>
        <input class="form-input" id="nu-newpw" type="password" placeholder="New password (optional)" />` : ''}
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="nu-save">${isEdit?'Save Changes':'Create User'}</button>
    </div>`);

  document.getElementById('nu-save')?.addEventListener('click', async () => {
    const name = document.getElementById('nu-name')?.value.trim();
    const role = document.getElementById('nu-role')?.value;
    if (!name || !role) { toast('Name and role required', 'danger'); return; }
    try {
      if (isEdit) {
        const body = { name, role, department: document.getElementById('nu-dept')?.value.trim()||'', active: document.getElementById('nu-active')?.value === 'true' };
        const newPw = document.getElementById('nu-newpw')?.value;
        if (newPw) body.newPassword = newPw;
        const updated = await PUT(`/users/${existing.id}`, body);
        const idx = S.iamUsers.findIndex(u=>u.id===existing.id);
        if (idx>-1) S.iamUsers[idx] = {...S.iamUsers[idx],...updated};
        toast('User updated', 'success');
      } else {
        const username  = document.getElementById('nu-username')?.value.trim();
        const email     = document.getElementById('nu-email')?.value.trim();
        const password  = document.getElementById('nu-password')?.value;
        if (!username || !email || !password) { toast('All fields required', 'danger'); return; }
        if (password.length < 8) { toast('Password must be ≥ 8 chars', 'danger'); return; }
        const created = await POST('/users', { username, email, name, role, department: document.getElementById('nu-dept')?.value.trim()||'', password });
        S.iamUsers.push(created);
        toast(`User "${name}" created`, 'success');
      }
      closeModal();
      renderContent();
    } catch(e) {
      toast(e.message||'Failed to save user', 'danger');
    }
  });
}

function openDeleteUserModal(userId) {
  const u = S.iamUsers.find(x=>x.id===userId);
  if (!u) return;
  openModal(`
    <div class="modal-header">
      <h3 style="color:var(--danger)">Delete User</h3>
      <button class="modal-close" data-action="close-modal">✕</button>
    </div>
    <div class="modal-body">
      <p style="color:var(--txt2)">Permanently delete <strong style="color:var(--txt)">${esc(u.name)}</strong> (@${esc(u.username)})?</p>
      <p style="color:var(--danger);margin-top:10px;font-size:13px">This cannot be undone. The user will lose all access immediately.</p>
    </div>
    <div class="modal-footer">
      <button class="btn-secondary" data-action="close-modal">Cancel</button>
      <button class="btn-primary" id="del-user-btn" style="background:var(--danger)">Delete User</button>
    </div>`);

  document.getElementById('del-user-btn')?.addEventListener('click', async () => {
    try {
      await DELETE(`/users/${u.id}`);
      S.iamUsers = S.iamUsers.filter(x=>x.id!==u.id);
      closeModal();
      renderContent();
      toast(`User "${u.name}" deleted`, 'danger');
    } catch(e) {
      toast(e.message||'Failed to delete user', 'danger');
    }
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   EVENT BINDING — single delegated listener on document
   Covers ALL clicks everywhere: content area, modals, sidebar, topbar.
   No per-element binding needed; works for dynamically injected HTML.
   ═══════════════════════════════════════════════════════════════════════════ */
function bindContentEvents() {
  // No-op: all clicks are handled by the document-level delegated listener
  // installed once in DOMContentLoaded (see bottom of file).
}

async function handleAction(e) {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const act = el.dataset.action;
  const id  = el.dataset.id;
  const tid = el.dataset.taskId;

  switch(act) {
    case 'goto-project':
      S.selectedProjectId = id;
      setView('project-detail');
      break;
    case 'new-project':
      if (can('projects:create')) openProjectModal(null);
      break;
    case 'edit-project':
      e.stopPropagation();
      if (can('projects:update')) openProjectModal(S.projects.find(p=>p.id===id));
      break;
    case 'delete-project':
      e.stopPropagation();
      if (can('projects:delete')) openDeleteProjectModal(id);
      break;
    case 'new-task':
      if (can('tasks:create')) openNewTaskModal();
      break;
    case 'task-detail':
      openTaskDetailModal(tid);
      break;
    case 'filter':
      S.filterStatus = el.dataset.status;
      renderContent();
      break;
    case 'issues-tab':
      S.issuesTab = el.dataset.tab;
      renderContent();
      break;
    case 'close-modal':
      closeModal();
      break;
    case 'new-user':
      if (can('users:create')) openNewUserModal(null);
      break;
    case 'edit-user':
      if (can('users:update')) openNewUserModal(S.iamUsers.find(u=>u.id===id));
      break;
    case 'delete-user':
      if (can('users:delete')) openDeleteUserModal(id);
      break;
    case 'cicd-fetch-branches': {
      const pid = el.dataset.projectId;
      const repoInput  = document.getElementById(`gh-repo-input-${pid}`);
      const tokenInput = document.getElementById(`gh-token-input-${pid}`);
      const repoUrl = repoInput ? repoInput.value.trim() : '';
      const token   = tokenInput ? tokenInput.value.trim() : '';
      if (!repoUrl) { toast('Enter a repository URL or owner/repo first', 'danger'); return; }
      const origLabel = el.textContent;
      el.disabled = true; el.textContent = 'Fetching…';
      try {
        const data = await POST('/github/branches', { repoUrl, token });
        S.ghBranches[pid] = { repoUrl, token, branches: data.branches, defaultBranch: data.defaultBranch };
        toast(`Found ${data.branches.length} branch(es)${data.defaultBranch ? ` · default: ${data.defaultBranch}` : ''}`, 'success');
        renderContent();
      } catch (e) {
        toast(e.message || 'Failed to fetch branches', 'danger');
      } finally {
        el.disabled = false; el.textContent = origLabel;
      }
      break;
    }
    case 'cicd-load-branches': {
      const pid = el.dataset.projectId;
      el.disabled = true;
      try {
        const data = await GET(`/projects/${pid}/github/branches`);
        S.ghBranches[pid] = { branches: data.branches };
        toast(`Loaded ${data.branches.length} branch(es)`, 'info');
        renderContent();
      } catch (e) {
        toast(e.message || 'Failed to load branches', 'danger');
      } finally {
        el.disabled = false;
      }
      break;
    }
    case 'cicd-connect': {
      const pid = el.dataset.projectId;
      const repoInput    = document.getElementById(`gh-repo-input-${pid}`);
      const tokenInput   = document.getElementById(`gh-token-input-${pid}`);
      const branchSelect = document.getElementById(`gh-branch-select-${pid}`);
      const repoUrl = repoInput ? repoInput.value.trim() : '';
      if (!repoUrl) { toast('Enter a repository URL or owner/repo', 'danger'); return; }
      const branch = branchSelect?.value || S.ghBranches[pid]?.defaultBranch || '';
      if (!branch) { toast('Fetch branches and pick one before connecting', 'danger'); return; }
      const token = tokenInput?.value.trim() || S.ghBranches[pid]?.token || '';
      try {
        await PUT(`/projects/${pid}/github`, { repoUrl, token, branch });
        delete S.ghBranches[pid];
        await loadProjects();
        await loadGithubCommits(pid);
        toast(`GitHub repo connected on branch "${branch}"`, 'success');
        renderContent();
      } catch (e) {
        toast(e.message || 'Failed to connect repo', 'danger');
      }
      break;
    }
    case 'cicd-disconnect': {
      const pid = el.dataset.projectId;
      try {
        await DELETE(`/projects/${pid}/github`);
        await loadProjects();
        delete S.githubCommits[pid];
        delete S.ghBranches[pid];
        toast('Disconnected from repository', 'info');
        renderContent();
      } catch (e) {
        toast(e.message || 'Failed to disconnect', 'danger');
      }
      break;
    }
        case 'export-job-card':
    case 'export-job-card-csv': {
      const monthInput = document.getElementById('jobcard-page-month') || document.getElementById('jobcard-month');
      const month = monthInput?.value;
      if (!month) { toast('Pick a month first', 'danger'); return; }
      const sources = Object.entries(S.jobCardSources).filter(([,v]) => v).map(([k]) => k).join(',') || 'commits,tasks,custom';
      const format = act === 'export-job-card-csv' ? 'csv' : 'pdf';
      const url = `${API_BASE}/reports/job-card?month=${month}&format=${format}&sources=${sources}`;
      try {
        const res = await fetch(url, { headers: { Authorization: `Bearer ${S.token}` } });
        if (!res.ok) { const d = await res.json().catch(()=>({})); throw new Error(d.error || 'Export failed'); }
        const blob = await res.blob();
        const dlUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = dlUrl;
        a.download = `Job-Card-${month}.${format}`;
        a.click();
        URL.revokeObjectURL(dlUrl);
      } catch (e) {
        toast(e.message || 'Export failed', 'danger');
      }
      break;
    }
    case 'goto-jobcard':
      await loadJobEntries(S.jobCardMonth);
      setView('jobcard');
      break;
    case 'new-job-entry':
      if (can('tasks:create')) openJobEntryModal(null);
      break;
    case 'edit-job-entry':
      if (can('tasks:update')) openJobEntryModal(S.jobEntries.find(e => e.id === id));
      break;
    case 'delete-job-entry': {
      if (!can('tasks:delete')) return;
      if (!confirm('Delete this job entry?')) return;
      try {
        await DELETE(`/job-entries/${id}`);
        S.jobEntries = S.jobEntries.filter(e => e.id !== id);
        toast('Job entry deleted', 'info');
        renderContent();
      } catch (e) {
        toast(e.message || 'Failed to delete', 'danger');
      }
      break;
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   LOGIN LOGIC
   ═══════════════════════════════════════════════════════════════════════════ */
function initLoginScreen() {
  const btn    = document.getElementById('login-btn');
  const errEl  = document.getElementById('login-error');
  const eyeBtn = document.getElementById('login-pw-eye');
  const pwInput= document.getElementById('login-password');

  eyeBtn?.addEventListener('click', () => {
    pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
  });

  async function attemptLogin() {
    const username = document.getElementById('login-username')?.value.trim();
    const password = document.getElementById('login-password')?.value;
    if (!username || !password) {
      errEl.style.display = '';
      errEl.textContent = 'Username and password are required.';
      return;
    }
    errEl.style.display = 'none';
    btn.disabled = true;
    document.getElementById('login-btn-label').style.display = 'none';
    document.getElementById('login-spinner').style.display = '';
    try {
      await doLogin(username, password);
      await loadProjects();
      if (can('users:read')) await loadIAMUsers();
      if (can('audit:read')) await loadAuditLog();
      showApp();
      renderAll();
      setView('dashboard');
    } catch(e) {
      errEl.style.display = '';
      errEl.textContent = e.data?.error || e.message || 'Login failed. Please try again.';
    } finally {
      btn.disabled = false;
      document.getElementById('login-btn-label').style.display = '';
      document.getElementById('login-spinner').style.display = 'none';
    }
  }

  btn?.addEventListener('click', attemptLogin);
  document.getElementById('login-password')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') attemptLogin();
  });
  document.getElementById('login-username')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('login-password')?.focus();
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   BOOT
   ═══════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  applyTheme();
  initLoginScreen();
  await new Promise(r => setTimeout(r, 1500));

  const valid = await verifyToken();
  if (valid) {
    await loadProjects();
    if (can('users:read')) await loadIAMUsers();
    if (can('audit:read')) await loadAuditLog();
    showApp();
    renderAll();
    setView('dashboard');
  } else {
    showLogin();
  }

  // Sidebar nav
  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const view = btn.dataset.view;
      if (view === 'iam' && can('users:read')) { await loadIAMUsers(); }
      if (view === 'audit' && can('audit:read')) { await loadAuditLog(); }
      if (view === 'cicd') {
        S.projects.filter(p => p.github).forEach(p => loadGithubCommits(p.id));
      }
      if (view === 'timeline') { loadCommitCalendar(); }
      if (view === 'jobcard') { await loadJobEntries(S.jobCardMonth); }
      if (view !== 'project-detail') S.selectedProjectId = null;
      setView(view);
      // Auto-close sidebar on mobile after nav
      if (window.innerWidth <= 640) {
        document.getElementById('sidebar')?.classList.remove('open-mobile');
        document.body.classList.remove('sidebar-open');
      }
    });
  });

  // Sidebar toggle — desktop: collapsed class; mobile: open-mobile class
  document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    const isMobile = window.innerWidth <= 640;
    if (isMobile) {
      const isOpen = sidebar.classList.toggle('open-mobile');
      document.body.classList.toggle('sidebar-open', isOpen);
    } else {
      S.sidebarOpen = !S.sidebarOpen;
      sidebar.classList.toggle('collapsed', !S.sidebarOpen);
    }
  });

  // Tap dimmer to close mobile sidebar
  document.getElementById('sidebar-dimmer')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.remove('open-mobile');
    document.body.classList.remove('sidebar-open');
  });

  // Theme toggle
  document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);

  // Logout
  document.getElementById('sidebar-logout-btn')?.addEventListener('click', async () => {
    if (confirm('Sign out?')) await doLogout();
  });

  // Topbar new project button
  document.getElementById('topbar-action')?.addEventListener('click', () => {
    if (can('projects:create')) openProjectModal(null);
  });

  // ── Single document-level delegated click handler ──────────────────────────
  // Handles ALL [data-action] clicks everywhere — content, modals, sidebar, topbar.
  // This is the ONLY event binding needed; no per-element addEventListener required.
  document.addEventListener('click', handleAction);

  document.addEventListener('change', async (e) => {
    const branchSel = e.target.closest('.gh-branch-switch');
    if (branchSel) {
      const pid = branchSel.dataset.projectId;
      const newBranch = branchSel.value;
      branchSel.disabled = true;
      try {
        await PUT(`/projects/${pid}/github`, { branch: newBranch });
        await loadProjects();
        await loadGithubCommits(pid);
        toast(`Switched to branch "${newBranch}"`, 'success');
      } catch (err) {
        toast(err.message || 'Failed to switch branch', 'danger');
        renderContent();
      } finally {
        branchSel.disabled = false;
      }
      return;
    }

    const monthSel = e.target.closest('.commit-cal-month');
    if (monthSel) {
      S.commitCalMonth = monthSel.value;
      S.commitCalendar = null; // show loading state while refetching
      renderContent();
      await loadCommitCalendar();
    }

    const jcMonth = e.target.closest('.jobcard-page-month');
    if (jcMonth) {
      S.jobCardMonth = jcMonth.value;
      await loadJobEntries(S.jobCardMonth);
      renderContent();
      return;
    }

    const jcSource = e.target.closest('.jobcard-source-toggle');
    if (jcSource) {
      S.jobCardSources[jcSource.dataset.source] = jcSource.checked;
    }
  });

  // Close modal when clicking the dark overlay backdrop (not the modal box itself)
  document.getElementById('modal-overlay')?.addEventListener('click', e => {
    if (e.target === document.getElementById('modal-overlay')) closeModal();
  });

  // Escape key closes modal
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
  });

  Neutralino.events.on('windowClose', async () => {
    await stopBackend();
    Neutralino.app.exit();
  });

  // Sidebar clicks are handled by the document-level delegated listener below.
});
