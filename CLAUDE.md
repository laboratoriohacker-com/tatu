# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Tatush (Tatu)** is an AI-Assisted DevSecOps platform — a security dashboard for DevSecOps teams. It provides real-time monitoring of Claude Code hooks that enforce security policies (secrets detection, destructive command blocking, PII/LGPD compliance, SAST scanning, dependency vulnerability checks, etc.).

## Monorepo Structure

```
tatush/
├── backend/          # FastAPI + SQLAlchemy (Python 3.11+)
│   ├── app/          # Application code (config, models, routes, main)
│   ├── tests/        # pytest test suite
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/         # React 18 + TypeScript + Vite + Tailwind CSS
│   ├── src/
│   │   ├── components/   # Shared UI (StatCard, Panel, SeverityBadge, etc.)
│   │   ├── hooks/        # useApi, useAuth, useWebSocket
│   │   ├── lib/          # API client and TypeScript types
│   │   └── pages/        # 6 dashboard pages
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── Makefile
└── docs/             # Specs and planning documents
```

## Development Commands (via Docker Compose)

All commands should be run via docker compose:

```bash
# Start all services (backend + frontend)
make dev

# Run backend tests
make test

# Lint frontend
make lint

# Build frontend
make build

# Start PostgreSQL only
make db

# Run database migrations
make migrate

# Seed sample data
make seed
```

## Architecture

- **Backend**: FastAPI with SQLAlchemy 2.0 async, Pydantic v2 settings, Alembic migrations
- **Frontend**: React 18 + TypeScript, Vite bundler, Tailwind CSS 4, React Router 6
- **Database**: PostgreSQL 16 (via Docker), SQLite for dev/test
- **Real-time**: WebSocket endpoint at `/api/v1/ws` for live alert streaming
- **Auth**: Password-based login with session cookies (itsdangerous)

### Dashboard Pages

- **Overview**: Stats, 24h timeline, recent alerts, compliance gauges, top hooks
- **Live Alerts**: WebSocket real-time feed with severity filters
- **Hooks**: Sortable performance table (triggers, blocks, block rate)
- **Compliance**: SOC2, LGPD, CPS234, ISO 27001, GDPR framework coverage
- **Developers**: Risk profile table with session activity
- **Audit Log**: Paginated event table with CSV/JSON export

## Key Domain Concepts

- **Hooks**: Security checks that run before/after Claude Code tool use (PreToolUse/PostToolUse events)
- **LGPD**: Brazilian General Data Protection Law — the PII detector targets Brazilian PII patterns (CPF, etc.)
- **CPS234**: Australian prudential standard for information security

## Design System

- Dark theme with emerald green (#10B981) accents
- JetBrains Mono font
- Geometric grid patterns

## IMPORTANT INSTRUCTIONS

- Always use docker compose to execute tests and other commands related to the application
- Lint the code
