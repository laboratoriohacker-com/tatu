# Tatu — AI-Assisted DevSecOps Platform

Tatu is a security dashboard for DevSecOps teams that monitors Claude Code hooks enforcing security policies: secrets detection, destructive command blocking, PII/LGPD compliance, SAST scanning, and dependency vulnerability checks.

## Architecture

```
tatush/
├── backend/       FastAPI + SQLAlchemy (Python 3.12)
├── frontend/      React 18 + TypeScript + Vite + Tailwind CSS
├── tatu-hook/     Claude Code security hook CLI (Python package)
├── rules/         Built-in YAML/YARA security rule templates
└── docker-compose.yml
```

**Hybrid hook system:** `tatu-hook` runs locally on developer machines as a Claude Code hook. It evaluates security rules locally for instant block/allow decisions, then reports events asynchronously to the Tatu dashboard API.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Git

### 1. Clone and configure

```bash
git clone https://github.com/your-org/tatush.git
cd tatush
cp .env.example .env
# Edit .env — set TATU_DASHBOARD_PASSWORD and TATU_SECRET_KEY
```

Generate a secret key:

```bash
openssl rand -hex 32
```

### 2. Start the platform

```bash
make dev
```

This starts:
- **Backend** at http://localhost:8000 (FastAPI API)
- **Frontend** at http://localhost:5173 (React dashboard)

### 3. Seed sample data

```bash
# Seed the 15 built-in hook configurations
make seed

# Generate 200 sample security events for testing
make generate-events
```

### 4. Open the dashboard

Go to http://localhost:5173 and log in with the password from your `.env` file.

## Development Commands

All commands run via Docker Compose:

```bash
make dev              # Start backend + frontend
make dev-backend      # Start backend only
make dev-frontend     # Start frontend only
make test             # Run backend tests (pytest)
make lint             # Lint frontend (ESLint)
make build            # Build frontend for production
make seed             # Seed hook configurations
make generate-events  # Generate sample events (COUNT=500 HOURS=72)
make db               # Start PostgreSQL only
make migrate          # Run database migrations
```

## Deploying to Production

### Docker Compose (single server)

1. Create a `.env` file with production values:

```bash
TATU_DASHBOARD_PASSWORD=<strong-password>
TATU_SECRET_KEY=<openssl-rand-hex-32>
TATU_DATABASE_URL=postgresql+asyncpg://tatu:tatu_dev@db:5432/tatu
TATU_CORS_ORIGINS=["https://tatu.your-domain.com"]
```

2. Start with PostgreSQL:

```bash
make db                # Start PostgreSQL
make migrate           # Run migrations
make seed              # Seed hooks
docker compose up -d   # Start all services
```

3. For production, build the frontend statically and serve via nginx or similar. The Vite dev server is not suitable for production.

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `TATU_DASHBOARD_PASSWORD` | Yes | — | Password for dashboard login |
| `TATU_SECRET_KEY` | Yes | — | Secret for session cookie signing |
| `TATU_DATABASE_URL` | No | `sqlite+aiosqlite:///./tatu.db` | Database connection string |
| `TATU_CORS_ORIGINS` | No | `["http://localhost:5173"]` | Allowed origins (JSON array) |
| `TATU_HOST` | No | `0.0.0.0` | API server host |
| `TATU_PORT` | No | `8000` | API server port |
| `TATU_LOG_LEVEL` | No | `info` | Log level |

## tatu-hook CLI

`tatu-hook` is a standalone Python CLI that runs as a Claude Code hook on developer machines. It evaluates security rules locally and reports events to the Tatu dashboard.

### Install

```bash
pip install ./tatu-hook
# Or with YARA support:
pip install "./tatu-hook[yara]"
```

### Initialize

```bash
# Create an API key in the dashboard first (Settings > API Keys)
tatu-hook init --api-url http://tatu.your-domain.com --api-key tatu_xxxxx
```

This creates `~/.tatu/manifest.json` and syncs the latest rules from the server.

### Configure Claude Code

Add to your `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "tatu-hook run --event session-start" }] }
    ],
    "PreToolUse": [
      { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook run --event pre" }] }
    ],
    "PostToolUse": [
      { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook run --event post" }] }
    ]
  }
}
```

### How it works

1. **SessionStart** — Syncs rules from the Tatu API (version check, downloads if outdated)
2. **PreToolUse/PostToolUse** — Evaluates content against cached rules (regex + optional YARA)
3. **Policy modes:**
   - `audit` (default) — Logs what would be blocked, never denies. Safe for onboarding.
   - `strict` — Actively blocks Claude Code operations that match rules.
4. Events are reported asynchronously to the dashboard (fire-and-forget, non-blocking)

### Local cache

Rules are cached at `~/.tatu/`:

```
~/.tatu/
├── manifest.json    # Version, API URL, API key
├── rules/           # Synced YAML templates
└── yara/            # Synced YARA rules
```

If the API is unreachable, `tatu-hook` falls back to cached rules silently.

## Built-in Rule Library

Tatu ships with 22 security rule templates across 6 categories:

| Category | Rules | Examples |
|---|---|---|
| **secrets** | 10 | AWS keys, GitHub tokens, Stripe keys, private keys, passwords |
| **pii** | 3 | Brazilian CPF/CNPJ (LGPD), email addresses |
| **destructive** | 3 | `rm -rf`, `DROP TABLE`, `git push --force` |
| **sast** | 3 | SQL injection, XSS, command injection |
| **files** | 2 | Protected paths (.env, SSH keys), lockfile modifications |
| **yara** | 1 | Private key multi-condition detection |

All built-in rules default to `mode: audit`. Customize via the Rules page in the dashboard or clone to custom for full editing.

## Dashboard Pages

- **Overview** — Stats, 24h event timeline, recent alerts, compliance gauges
- **Live Alerts** — Real-time WebSocket feed with severity + audit filters
- **Hooks** — Sortable performance table (triggers, blocks, block rate)
- **Rules** — Search, filter, edit security rules with YAML/YARA editor
- **Compliance** — SOC2, LGPD, CPS234, ISO 27001 framework coverage
- **Developers** — Risk profile table with session activity
- **Audit Log** — Paginated event history with CSV/JSON export

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | — | Dashboard login |
| `POST` | `/api/v1/auth/api-keys` | Cookie | Create API key |
| `POST` | `/api/v1/events` | API Key | Ingest hook event |
| `GET` | `/api/v1/overview/stats` | Cookie | Dashboard stats |
| `GET` | `/api/v1/overview/timeline` | Cookie | 24h event timeline |
| `GET` | `/api/v1/alerts` | Cookie | Paginated alerts |
| `GET` | `/api/v1/hooks` | Cookie | Hook performance |
| `GET` | `/api/v1/rules` | Cookie | List rules |
| `GET` | `/api/v1/rules/{id}` | Cookie | Get single rule |
| `PUT` | `/api/v1/rules/{id}` | Cookie | Update rule |
| `POST` | `/api/v1/rules/{id}/clone` | Cookie | Clone built-in to custom |
| `GET` | `/api/v1/rules/sync` | — | Rule sync for tatu-hook |
| `GET` | `/api/v1/compliance` | Cookie | Compliance metrics |
| `GET` | `/api/v1/developers` | Cookie | Developer risk profiles |
| `GET` | `/api/v1/audit` | Cookie | Audit log with export |
| `GET` | `/api/v1/health` | — | Health check |
| `WS` | `/api/v1/ws` | Cookie | Real-time event stream |

## Compliance Frameworks

Tatu tracks coverage against:
- **SOC2** — Trust Services Criteria
- **LGPD** — Brazilian General Data Protection Law (PII: CPF, CNPJ)
- **CPS234** — Australian prudential standard for information security
- **ISO 27001** — Information security management

## License

MIT
