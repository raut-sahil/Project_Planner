# ◈ Planner — Project Command Center v2

Internal org project management system with IAM, RBAC, IP restriction, and full audit logging.

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env — especially JWT_SECRET and ALLOWED_IP

# 3. Start the server
npm start
# Open: http://127.0.0.1:3000
```

---

## Default Credentials

| Username     | Password       | Role        |
|--------------|----------------|-------------|
| superadmin   | Admin@1234     | Super Admin |
| manager01    | Manager@1234   | Manager     |
| dev01        | Dev@1234       | Developer   |
| viewer01     | View@1234      | Viewer      |

⚠️  Change all passwords immediately after first login.

---

## Role Permissions

| Permission          | SuperAdmin | Admin | Manager | Developer | Viewer |
|---------------------|:----------:|:-----:|:-------:|:---------:|:------:|
| projects:create     | ✓ | ✓ | ✓ | — | — |
| projects:update     | ✓ | ✓ | ✓ | — | — |
| projects:delete     | ✓ | ✓ | — | — | — |
| tasks:create        | ✓ | ✓ | ✓ | — | — |
| tasks:update        | ✓ | ✓ | ✓ | ✓ | — |
| tasks:delete        | ✓ | ✓ | ✓ | — | — |
| issues:create       | ✓ | ✓ | ✓ | ✓ | — |
| issues:resolve      | ✓ | ✓ | ✓ | ✓ | — |
| users:read          | ✓ | ✓ | ✓ | — | — |
| users:create        | ✓ | — | — | — | — |
| users:delete        | ✓ | — | — | — | — |
| audit:read          | ✓ | ✓ | — | — | — |
| settings:manage     | ✓ | — | — | — | — |

---

## Security Features

- **IP Allowlist** — Requests from unlisted IPs get HTTP 403
- **JWT Auth** — 8-hour expiring tokens, re-auth required after expiry
- **bcrypt Passwords** — 12 rounds, no plaintext ever stored
- **Account Lockout** — 5 failed attempts locks for 15 minutes
- **Audit Log** — Every action logged with IP, user, and timestamp
- **RBAC** — Server-side permission checks on every endpoint
- **CORS** — Restricted to localhost / intranet origins only

---

## API Endpoints

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | /api/auth/login | Login, returns JWT |
| GET  | /api/auth/me | Current user info |
| POST | /api/auth/logout | Logout (audit logged) |
| POST | /api/auth/change-password | Change own password |

### Projects
| Method | Path | Permission |
|--------|------|------------|
| GET    | /api/projects | projects:read |
| POST   | /api/projects | projects:create |
| PUT    | /api/projects/:id | projects:update |
| DELETE | /api/projects/:id | projects:delete |

### Tasks & Issues
| Method | Path | Permission |
|--------|------|------------|
| POST   | /api/projects/:id/tasks | tasks:create |
| PUT    | /api/projects/:id/tasks/:tid | tasks:update |
| DELETE | /api/projects/:id/tasks/:tid | tasks:delete |
| POST   | /api/projects/:id/tasks/:tid/issues | issues:create |
| PUT    | /api/projects/:id/tasks/:tid/issues/:iid | issues:resolve |

### Users (IAM)
| Method | Path | Permission |
|--------|------|------------|
| GET    | /api/users | users:read |
| POST   | /api/users | users:create |
| PUT    | /api/users/:id | users:update |
| DELETE | /api/users/:id | users:delete |

### System
| Method | Path | Permission |
|--------|------|------------|
| GET    | /api/audit | audit:read |
| GET    | /api/settings | settings:manage |
| PUT    | /api/settings | settings:manage |
| GET    | /api/health | public |

---

## Environment Variables

```env
PORT=3000               # Server port
JWT_SECRET=<64+ chars>  # Change this! Strong random string
ALLOWED_IP=127.0.0.1   # Only IP allowed to access the system
ALLOWED_IPS=10.0.0.1   # Additional IPs (optional, comma-separated)
DB_PATH=./db.json       # Path to JSON database
JWT_EXPIRY=8h           # Token expiry duration
MAX_LOGIN_ATTEMPTS=5    # Failed attempts before lockout
LOCKOUT_SECONDS=900     # Lockout duration (15 min)
```

---

## Database

Data is stored in `db.json` as structured JSON:
- `users[]` — IAM user accounts with hashed passwords
- `projects[]` — Projects with embedded tasks and issues
- `auditLog[]` — Tamper-evident action log (last 500 entries)
- `config{}` — System configuration

