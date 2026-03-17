# Tatu Dashboard & API — Design Spec

## Overview

Tatu is an open-source AI-Assisted DevSecOps platform that monitors Claude Code security hooks in real time. This spec covers the **dashboard + API** (this repo). The hooks plugin is a separate project.

**Stack:** FastAPI (Python) backend, React + Vite + Tailwind CSS frontend, SQLAlchemy with PostgreSQL (prod) / SQLite (dev).

**Monorepo:** Single repo with `backend/` and `frontend/` directories.

## Architecture

```
┌─────────────────────────────────────────┐
│  Hooks Plugin (separate project)        │
│  Secrets Leak Prevention, Cmd Blocker,  │
│  PII Detector, SAST Scanner, ...        │
└──────────────┬──────────────────────────┘
               │ HTTP POST /api/v1/events
               │ (API key in X-API-Key header)
               ▼
┌─────────────────────────────────────────┐
│  TATUSH MONOREPO                        │
│                                         │
│  backend/ (FastAPI)                     │
│  ├── Event ingestion endpoint           │
│  ├── Dashboard query endpoints          │
│  ├── WebSocket for real-time updates    │
│  └── SQLAlchemy → PostgreSQL / SQLite   │
│                                         │
│  frontend/ (React + Vite + Tailwind)    │
│  ├── 6 dashboard tabs                   │
│  ├── WebSocket client for live updates  │
│  └── Dark theme, JetBrains Mono         │
└─────────────────────────────────────────┘
```

### Authentication

- **Event ingestion:** API key in `X-API-Key` header. Keys are hashed (never stored plaintext). Multiple keys supported with revocation. Max request body: 1MB.
- **Dashboard access:** Shared password configured via environment variable. Returns a signed cookie (via `itsdangerous`) — stateless, no server-side session store needed.
- **WebSocket:** Authenticated via session cookie (validated on connection upgrade).

## Data Model

### events

The single source of truth. All dashboard views are computed from this table.

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | Primary key |
| timestamp | datetime (UTC) | When the event occurred |
| hook_name | string | e.g. "Secrets Leak Prevention" |
| hook_event | enum | PreToolUse, PostToolUse, Stop, SessionStart, SessionEnd, UserPromptSubmit, Notification, PreCompact |
| severity | enum | critical, warning, info |
| status | enum | blocked, warning, allowed, clean |
| message | text | Human-readable description |
| developer | string | Developer identifier |
| repository | string | Repo where it happened |
| session_id | string | Claude Code session ID |
| tool_name | string (nullable) | Tool that triggered the hook. Null for non-tool events (SessionStart, SessionEnd, etc.) |
| metadata | JSON | Flexible payload (command, file path, CVE details, etc.) |

### hooks

Registered hook configurations and their compliance mappings.

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | Primary key |
| name | string | Display name |
| category | enum | offensive_guardrails, secure_sdlc, compliance_audit, incident_response |
| hook_event | enum | Which lifecycle event it fires on |
| matcher | string | Tool matcher pattern |
| enabled | boolean | Active/inactive toggle |
| compliance_mappings | JSON | e.g. `["SOC2 CC6.1", "LGPD Art. 46", "ISO 27001 A.9.4"]` |

### api_keys

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | Primary key |
| key_hash | string | Hashed API key |
| label | string | Human-readable name |
| created_at | datetime | When issued |
| last_used_at | datetime | Last event received |
| active | boolean | Revocation support |

## API Endpoints

All prefixed with `/api/v1/`. All query endpoints support `?period=24h|7d|30d` (default: 24h).

### Pagination

Paginated endpoints (`/alerts`, `/audit`) use offset-based pagination: `?page=1&per_page=50`. Default page size: 50, max: 200. Period filter applies before pagination (scopes the date range, then paginates within it). Response includes `total`, `page`, `per_page`, and `pages` fields.

### Error Responses

All errors use FastAPI's default format: `{"detail": "Error message"}`. Status codes: 400 (bad request), 401 (missing/invalid auth), 403 (valid auth but insufficient), 422 (validation error), 429 (rate limited), 500 (server error).

### Health Check

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Returns `{"status": "ok", "db": "connected"}`. No auth required. |

### Event Ingestion (API key auth)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/events` | Ingest hook event. Broadcasts to WebSocket subscribers. |

### Dashboard Queries (session cookie auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/overview/stats` | KPI summary: total events, blocks, active sessions, secrets caught |
| GET | `/overview/timeline` | Hourly event/block counts for timeline chart |
| GET | `/alerts` | Paginated alerts with filters: `?severity=&hook=&developer=&status=` |
| GET | `/hooks` | List hooks with computed stats (triggers, blocks, block rate) |
| GET | `/compliance` | Compliance frameworks with coverage percentages, control mappings |
| GET | `/developers` | Developer list with session count, block count, risk level |
| GET | `/audit` | Paginated audit log. Supports `?format=csv` and `?format=json` for export |

### WebSocket

| Path | Description |
|------|-------------|
| WS `/ws` | Real-time event stream. New events pushed as they arrive. |

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Validate shared password, return session cookie |
| POST | `/auth/api-keys` | Generate new API key (returns plaintext once) |
| GET | `/auth/api-keys` | List API keys (no secrets exposed) |
| DELETE | `/auth/api-keys/{id}` | Revoke an API key |

## Dashboard Tabs

All 6 tabs from the prototype:

1. **Overview** — 4 KPI stat cards (total events, blocks, active sessions, secrets caught), 24h event timeline bar chart, recent alerts list, compliance coverage gauges, hook effectiveness ranking.
2. **Live Alerts** — Real-time alert feed via WebSocket, severity filter buttons (All/Critical/Warning/Info), expandable alert detail with hook, event, developer, and repository info.
3. **Hooks** — Performance table: hook name, triggers, blocks, block rate, active status. Sortable columns.
4. **Compliance** — Per-framework stat cards (SOC2, LGPD, CPS234, ISO 27001) with coverage percentage, control mapping table showing which hooks cover which framework controls.
5. **Developers** — Developer risk profile table: name, session activity bar, session count, block count, risk level badge (high/low).
6. **Audit Log** — Full event table: timestamp, developer, hook, event detail, result. Display labels map from status enum: blocked→DENY, warning→WARN, allowed→ALLOW, clean→PASS. Events from Session Audit Logger display as LOG. Export buttons for CSV and JSON.

### Business Logic Definitions

- **Active sessions:** Count of distinct `session_id` values that have at least one event in the last 30 minutes.
- **Developer risk level:** "high" if block count > 5 within the selected period, otherwise "low".
- **Compliance coverage:** `(number of enabled hooks mapped to framework) / (total controls in framework) * 100`. Total controls per framework are stored in the `hooks` table compliance_mappings and defined at seed time: SOC2=14, LGPD=8, CPS234=12, ISO 27001=18.

## Design System

### Colors (Tailwind custom theme as `tatu-*`)

| Token | Hex | Usage |
|-------|-----|-------|
| bg | #0A0E17 | Page background |
| surface | #111827 | Cards, panels, sidebar |
| surface-alt | #151D2E | Table headers, hover states |
| border | #1E293B | Borders, dividers |
| border-hover | #334155 | Interactive border states |
| text | #E2E8F0 | Primary text |
| text-muted | #94A3B8 | Secondary text |
| text-dim | #64748B | Labels, timestamps |
| accent | #10B981 | Primary accent (emerald green) |
| accent-dim | #059669 | Accent hover state |
| accent-glow | rgba(16,185,129,0.15) | Accent backgrounds |
| critical | #EF4444 | Critical severity, blocked status |
| warn | #F59E0B | Warning severity |
| info | #3B82F6 | Info severity |

### Typography

JetBrains Mono throughout (monospace). Fallbacks: SF Mono, Fira Code, system monospace.

### Components

- **StatCard** — Gradient accent bar at top, uppercase label, large KPI value, subtitle
- **SeverityBadge** — Colored pill: CRITICAL (red), WARNING (amber), INFO (blue)
- **StatusDot** — Glowing 7px circle: blocked (red), warning (amber), allowed/clean (green)
- **Panel** — Surface background, border, 8px radius, 20px padding
- **TimelineChart** — Vertical bar chart with green event bars and red block overlay
- **ComplianceGauge** — Horizontal progress bar with framework label and fraction
- **GridPattern** — Subtle 48px grid background (fixed position)
- **TatuLogo** — Geometric hexagonal armadillo shell SVG

## Project Structure

```
tatush/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app, CORS, middleware
│   │   ├── config.py            # Settings via pydantic-settings
│   │   ├── database.py          # SQLAlchemy engine, session factory
│   │   ├── auth.py              # API key validation, password check
│   │   ├── models/              # SQLAlchemy models
│   │   │   ├── event.py
│   │   │   ├── hook.py
│   │   │   └── api_key.py
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   │   ├── event.py
│   │   │   ├── hook.py
│   │   │   ├── auth.py
│   │   │   └── stats.py
│   │   ├── routers/             # API route handlers
│   │   │   ├── overview.py
│   │   │   ├── events.py
│   │   │   ├── alerts.py
│   │   │   ├── hooks.py
│   │   │   ├── compliance.py
│   │   │   ├── developers.py
│   │   │   ├── audit.py
│   │   │   └── auth.py
│   │   └── services/            # Business logic
│   │       ├── event_service.py
│   │       ├── stats_service.py
│   │       └── websocket_manager.py
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_*.py
│   ├── alembic/                 # DB migrations
│   ├── alembic.ini
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx              # Router, layout, auth gate
│   │   ├── components/          # Shared UI components
│   │   ├── pages/               # One per dashboard tab
│   │   ├── hooks/               # useWebSocket, useApi, useAuth
│   │   └── lib/                 # api.ts, types.ts, colors.ts
│   ├── index.html
│   ├── tailwind.config.ts
│   ├── vite.config.ts
│   ├── package.json
│   └── tsconfig.json
├── docker-compose.yml           # PostgreSQL for prod-like local setup
├── .env.example                 # See Configuration section
├── Makefile                     # dev, test, lint, build shortcuts
├── README.md
├── LICENSE
└── CLAUDE.md
```

## Configuration

Environment variables (all prefixed with `TATU_`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TATU_DATABASE_URL` | No | `sqlite:///./tatu.db` | Database connection string. Use `postgresql://...` in production. |
| `TATU_DASHBOARD_PASSWORD` | Yes | — | Shared password for dashboard login |
| `TATU_SECRET_KEY` | Yes | — | Secret for signing session cookies (generate with `openssl rand -hex 32`) |
| `TATU_CORS_ORIGINS` | No | `http://localhost:5173` | Comma-separated allowed origins |
| `TATU_HOST` | No | `0.0.0.0` | Bind host |
| `TATU_PORT` | No | `8000` | Bind port |
| `TATU_LOG_LEVEL` | No | `info` | Logging level |

### Known Limitations (MVP)

- **SQLite dev mode:** JSON column queries (filtering on `metadata` fields) are not supported on SQLite. Use Docker Compose with PostgreSQL for full feature parity.
- **Single-worker WebSocket:** The in-memory WebSocket manager does not broadcast across multiple uvicorn workers. Run with a single worker or add Redis pub/sub for multi-worker deployments.

## Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backend framework | FastAPI | Async, WebSocket support, auto OpenAPI docs |
| Frontend framework | React + Vite | Rich interactivity, separate SPA |
| CSS framework | Tailwind CSS | Utility-first, custom theme support |
| Database | PostgreSQL (prod) / SQLite (dev) | SQLAlchemy abstraction, zero-config dev |
| Repo structure | Monorepo | Simple setup, single CI, easy for contributors |
| Hook→API contract | HTTP POST + API key | Stateless, works everywhere |
| Dashboard auth | Shared password | Low complexity for MVP, upgradeable later |
| Real-time updates | WebSocket | Instant live alerts without polling |
| MVP scope | All 6 tabs, no external integrations | Full monitoring experience, no SIEM/Slack yet |
