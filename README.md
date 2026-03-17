# Tatu — AI-Assisted DevSecOps Platform

Tatu is a security dashboard for DevSecOps teams that monitors Claude Code hooks enforcing security policies: secrets detection, destructive command blocking, PII/LGPD compliance, SAST scanning, and dependency vulnerability checks.

## Architecture

```
tatush/
├── backend/       FastAPI + SQLAlchemy (Python 3.12)
├── frontend/      React 18 + TypeScript + Vite + Tailwind CSS
├── tatu-hook/     Claude Code security hook CLI (Python package)
├── rules/         Built-in YAML/YARA security rule templates
├── k8s/           Kubernetes deployment manifests
└── docker-compose.yml
```

**Hybrid hook system:** `tatu-hook` runs locally on developer machines as a Claude Code hook. It evaluates security rules locally for instant block/allow decisions, then reports events asynchronously to the Tatu dashboard API.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ (for tatu-hook)
- Git

### 1. Clone and configure

```bash
git clone https://github.com/laboratoriohacker-com/tatu.git
cd tatu
cp .env.example .env
# Edit .env — set TATU_SECRET_KEY and TATU_ADMIN_EMAIL
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
# Seed the built-in security rules
make seed

# Generate sample security events for testing
make generate-events
```

### 4. Install tatu-hook on developer machines

```bash
# From PyPI
pip install tatu-hook

# Or with YARA support
pip install "tatu-hook[yara]"

# Or from source (for development)
pip install ./tatu-hook
```

### 5. Initialize tatu-hook

Create an API key in the dashboard (Settings > API Keys), then:

```bash
tatu-hook init --api-url http://localhost:8000 --api-key tatu_xxxxx
```

This does three things:
1. Creates `~/.tatu/manifest.json` with your API configuration
2. Syncs the latest security rules from the server
3. Registers hooks in `~/.claude/settings.json` automatically

**Options:**
- `--scope project` — register hooks in `.claude/settings.json` (current directory only)
- `--no-register` — skip hook registration (for users who manage settings externally)

### 6. Open the dashboard

Go to http://localhost:5173 and log in with the email from your `.env` file.

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
TATU_SECRET_KEY=<openssl-rand-hex-32>
TATU_ADMIN_EMAIL=admin@your-domain.com
TATU_DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/tatu
TATU_CORS_ORIGINS=["https://tatu.your-domain.com"]
TATU_SMTP_HOST=smtp.your-provider.com
TATU_SMTP_PORT=587
TATU_SMTP_USER=your-smtp-user
TATU_SMTP_PASSWORD=your-smtp-password
TATU_SMTP_USE_TLS=true
TATU_SMTP_FROM=noreply@your-domain.com
```

2. Start with PostgreSQL:

```bash
make db                # Start PostgreSQL
make migrate           # Run migrations
make seed              # Seed rules
docker compose up -d   # Start all services
```

### Kubernetes

Plain YAML manifests are provided in `k8s/`. Assumes an external PostgreSQL and nginx ingress controller.

```bash
# Edit k8s/secret.yaml and k8s/configmap.yaml with your values
# Edit k8s/ingress.yaml with your domain
kubectl apply -f k8s/
```

### Docker Images

Production images are published to GitHub Container Registry on every push to main and on tags:

- `ghcr.io/laboratoriohacker-com/tatu-backend:latest`
- `ghcr.io/laboratoriohacker-com/tatu-frontend:latest`

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `TATU_SECRET_KEY` | Yes | — | Secret for session cookie signing |
| `TATU_ADMIN_EMAIL` | Yes | — | Admin email for OTP login |
| `TATU_DATABASE_URL` | No | `sqlite+aiosqlite:///./tatu.db` | Database connection string |
| `TATU_CORS_ORIGINS` | No | `["http://localhost:5173"]` | Allowed origins (JSON array) |
| `TATU_HOST` | No | `0.0.0.0` | API server host |
| `TATU_PORT` | No | `8000` | API server port |
| `TATU_LOG_LEVEL` | No | `info` | Log level |
| `TATU_SMTP_HOST` | No | — | SMTP server for OTP emails |
| `TATU_SMTP_PORT` | No | `587` | SMTP port |
| `TATU_SMTP_USER` | No | — | SMTP username |
| `TATU_SMTP_PASSWORD` | No | — | SMTP password |
| `TATU_SMTP_USE_TLS` | No | `false` | Use TLS for SMTP |
| `TATU_SMTP_FROM` | No | `noreply@tatu.local` | From address for emails |

## tatu-hook CLI

`tatu-hook` is a standalone Python CLI that runs as a Claude Code hook on developer machines. It evaluates security rules locally and reports events to the Tatu dashboard.

### How it works

1. **SessionStart** — Syncs rules from the Tatu API (version check, downloads if outdated)
2. **PreToolUse/PostToolUse** — Evaluates content against cached rules (regex + optional YARA)
3. **Pre-scan** — For Read operations, the hook opens and scans the file before Claude reads it, blocking sensitive content from ever entering Claude's context
4. **Policy modes:**
   - `audit` (default) — Logs what would be blocked, never denies. Safe for onboarding.
   - `strict` — Actively blocks Claude Code operations that match rules.
5. Events are reported asynchronously to the dashboard (fire-and-forget, non-blocking)

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

Tatu ships with 46 security rule templates across 6 categories:

| Category | Examples |
|---|---|
| **secrets** | AWS keys, GitHub tokens, Stripe keys, private keys, passwords, API keys |
| **pii** | Brazilian CPF/CNPJ (LGPD), email addresses, credit cards, IBAN, passports |
| **destructive** | `rm -rf`, `DROP TABLE`, `git push --force`, `chmod 777`, `dd`, Docker prune |
| **sast** | SQL injection, XSS, command injection, unsafe YAML load, weak crypto |
| **files** | Protected paths (.env, SSH keys), lockfile modifications, Docker socket |
| **yara** | Private key multi-condition detection |

All built-in rules default to `mode: audit`. Customize via the Rules page in the dashboard or clone to custom for full editing.

## Dashboard Pages

- **Overview** — Stats, 24h event timeline, recent alerts, compliance gauges
- **Live Alerts** — Real-time WebSocket feed with severity + audit filters, pagination
- **Rules** — Search, filter, edit security rules with YAML/YARA editor
- **Compliance** — SOC2, LGPD, CPS234, ISO 27001, GDPR, DORA framework coverage
- **Developers** — Risk profile table with session activity
- **Audit Log** — Paginated event history with CSV/JSON export
- **Settings** — API keys, user management, invitations

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | — | Request OTP login |
| `POST` | `/api/v1/auth/verify-otp` | — | Verify OTP code |
| `POST` | `/api/v1/auth/api-keys` | Cookie | Create API key |
| `POST` | `/api/v1/events` | API Key | Ingest hook event |
| `GET` | `/api/v1/overview/stats` | Cookie | Dashboard stats |
| `GET` | `/api/v1/overview/timeline` | Cookie | 24h event timeline |
| `GET` | `/api/v1/alerts` | Cookie | Paginated alerts |
| `GET` | `/api/v1/rules` | Cookie | List rules |
| `GET` | `/api/v1/rules/{id}` | Cookie | Get single rule |
| `PUT` | `/api/v1/rules/{id}` | Cookie | Update rule |
| `POST` | `/api/v1/rules/{id}/clone` | Cookie | Clone built-in to custom |
| `GET` | `/api/v1/rules/sync` | API Key | Rule sync for tatu-hook |
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
- **GDPR** — General Data Protection Regulation
- **DORA** — Digital Operational Resilience Act

## License

MIT
