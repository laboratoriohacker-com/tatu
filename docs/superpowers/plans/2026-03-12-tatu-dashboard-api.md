# Tatu Dashboard & API Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Tatu DevSecOps dashboard — a FastAPI backend for ingesting and querying security hook events, plus a React/Tailwind frontend with 6 dashboard tabs showing real-time security monitoring.

**Architecture:** Monorepo with `backend/` (FastAPI + SQLAlchemy) and `frontend/` (React + Vite + Tailwind). Events are ingested via authenticated HTTP POST, stored in PostgreSQL (or SQLite for dev), and broadcast to the frontend via WebSocket for live updates.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy 2.0, Alembic, Pydantic v2, itsdangerous, pytest, React 18, TypeScript, Vite, Tailwind CSS 3, React Router 6.

**Spec:** `docs/superpowers/specs/2026-03-12-tatu-dashboard-api-design.md`

---

## Chunk 1: Backend Foundation

### Task 1: Project scaffolding and dependencies

**Files:**
- Create: `backend/requirements.txt`
- Create: `backend/app/__init__.py`
- Create: `.env.example`

- [ ] **Step 1: Create `backend/requirements.txt`**

```
fastapi==0.115.*
uvicorn[standard]==0.34.*
sqlalchemy[asyncio]==2.0.*
alembic==1.14.*
pydantic-settings==2.7.*
itsdangerous==2.2.*
python-multipart==0.0.*
aiosqlite==0.21.*
asyncpg==0.30.*
passlib[bcrypt]==1.7.*
pytest==8.*
pytest-asyncio==0.25.*
httpx==0.28.*
```

- [ ] **Step 2: Create `.env.example`**

```
# Required
TATU_DASHBOARD_PASSWORD=changeme
TATU_SECRET_KEY=generate-with-openssl-rand-hex-32

# Optional
TATU_DATABASE_URL=sqlite+aiosqlite:///./tatu.db
TATU_CORS_ORIGINS=http://localhost:5173
TATU_HOST=0.0.0.0
TATU_PORT=8000
TATU_LOG_LEVEL=info
```

- [ ] **Step 3: Create `backend/app/__init__.py`**

Empty file.

- [ ] **Step 4: Install dependencies and verify**

```bash
cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

Expected: All packages install without errors.

- [ ] **Step 5: Commit**

```bash
git add backend/requirements.txt backend/app/__init__.py .env.example
git commit -m "feat: scaffold backend project with dependencies"
```

---

### Task 2: Configuration module

**Files:**
- Create: `backend/app/config.py`
- Create: `backend/tests/__init__.py`
- Create: `backend/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_config.py
import os
import pytest


def test_settings_loads_defaults():
    """Settings should have sensible defaults for non-required fields."""
    os.environ.setdefault("TATU_DASHBOARD_PASSWORD", "testpass")
    os.environ.setdefault("TATU_SECRET_KEY", "testsecret")
    from app.config import settings

    assert settings.database_url == "sqlite+aiosqlite:///./tatu.db"
    assert settings.cors_origins == ["http://localhost:5173"]
    assert settings.host == "0.0.0.0"
    assert settings.port == 8000
    assert settings.log_level == "info"


def test_settings_requires_password():
    """Settings should fail if TATU_DASHBOARD_PASSWORD is not set."""
    os.environ.pop("TATU_DASHBOARD_PASSWORD", None)
    os.environ.setdefault("TATU_SECRET_KEY", "testsecret")
    # pydantic-settings will raise ValidationError for missing required fields
    from pydantic import ValidationError
    from importlib import reload
    import app.config

    with pytest.raises(ValidationError):
        reload(app.config)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && source venv/bin/activate && python -m pytest tests/test_config.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'app.config'`

- [ ] **Step 3: Write the implementation**

```python
# backend/app/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "TATU_"}

    database_url: str = "sqlite+aiosqlite:///./tatu.db"
    dashboard_password: str
    secret_key: str
    cors_origins: list[str] = ["http://localhost:5173"]
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"


settings = Settings()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_config.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/config.py backend/tests/
git commit -m "feat: add configuration module with pydantic-settings"
```

---

### Task 3: Database setup and SQLAlchemy models

**Files:**
- Create: `backend/app/database.py`
- Create: `backend/app/models/__init__.py`
- Create: `backend/app/models/event.py`
- Create: `backend/app/models/hook.py`
- Create: `backend/app/models/api_key.py`
- Create: `backend/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_models.py
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from datetime import datetime, timezone
import uuid

from app.models import Base
from app.models.event import Event
from app.models.hook import Hook
from app.models.api_key import ApiKey


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_event(db_session: AsyncSession):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name="Secrets Leak Prevention",
        hook_event="PreToolUse",
        severity="critical",
        status="blocked",
        message="AWS key detected in config.py",
        developer="carlos.m",
        repository="payments-api",
        session_id="sess-123",
        tool_name="Write",
        metadata_={"file_path": "config.py"},
    )
    db_session.add(event)
    await db_session.commit()

    result = await db_session.get(Event, event.id)
    assert result is not None
    assert result.hook_name == "Secrets Leak Prevention"
    assert result.severity == "critical"
    assert result.tool_name == "Write"
    assert result.metadata_ == {"file_path": "config.py"}


@pytest.mark.asyncio
async def test_create_event_nullable_tool_name(db_session: AsyncSession):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name="Env Hardening",
        hook_event="SessionStart",
        severity="info",
        status="allowed",
        message="Environment validated",
        developer="julio.df",
        repository="pentest-tools",
        session_id="sess-456",
        tool_name=None,
        metadata_={},
    )
    db_session.add(event)
    await db_session.commit()

    result = await db_session.get(Event, event.id)
    assert result.tool_name is None


@pytest.mark.asyncio
async def test_create_hook(db_session: AsyncSession):
    hook = Hook(
        id=uuid.uuid4(),
        name="Secrets Leak Prevention",
        category="offensive_guardrails",
        hook_event="PreToolUse",
        matcher="Bash|Write|Edit",
        enabled=True,
        compliance_mappings=["SOC2 CC6.1", "LGPD Art. 46"],
    )
    db_session.add(hook)
    await db_session.commit()

    result = await db_session.get(Hook, hook.id)
    assert result.name == "Secrets Leak Prevention"
    assert result.enabled is True
    assert "SOC2 CC6.1" in result.compliance_mappings


@pytest.mark.asyncio
async def test_create_api_key(db_session: AsyncSession):
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash="hashed_value_here",
        label="production-hooks",
        created_at=datetime.now(timezone.utc),
        active=True,
    )
    db_session.add(api_key)
    await db_session.commit()

    result = await db_session.get(ApiKey, api_key.id)
    assert result.label == "production-hooks"
    assert result.active is True
    assert result.last_used_at is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_models.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `backend/app/database.py`**

```python
# backend/app/database.py
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.config import settings

engine = create_async_engine(settings.database_url, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
```

- [ ] **Step 4: Write `backend/app/models/__init__.py`**

```python
# backend/app/models/__init__.py
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
```

- [ ] **Step 5: Write `backend/app/models/event.py`**

```python
# backend/app/models/event.py
import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    hook_name: Mapped[str] = mapped_column(String(255))
    hook_event: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    developer: Mapped[str] = mapped_column(String(255))
    repository: Mapped[str] = mapped_column(String(255))
    session_id: Mapped[str] = mapped_column(String(255))
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
```

- [ ] **Step 6: Write `backend/app/models/hook.py`**

```python
# backend/app/models/hook.py
import uuid
from sqlalchemy import String, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class Hook(Base):
    __tablename__ = "hooks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(50))
    hook_event: Mapped[str] = mapped_column(String(50))
    matcher: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    compliance_mappings: Mapped[list] = mapped_column(JSON, default=list)
```

- [ ] **Step 7: Write `backend/app/models/api_key.py`**

```python
# backend/app/models/api_key.py
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    key_hash: Mapped[str] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_models.py -v
```

Expected: All 4 tests PASS

- [ ] **Step 9: Commit**

```bash
git add backend/app/database.py backend/app/models/
git commit -m "feat: add database setup and SQLAlchemy models (event, hook, api_key)"
```

---

### Task 4: Alembic migrations setup

**Files:**
- Create: `backend/alembic.ini`
- Create: `backend/alembic/env.py`
- Create: `backend/alembic/script.py.mako`
- Create: `backend/alembic/versions/` (directory)

- [ ] **Step 1: Initialize Alembic**

```bash
cd backend && source venv/bin/activate && alembic init alembic
```

- [ ] **Step 2: Edit `backend/alembic/env.py`**

Replace the generated `env.py` with an async-aware version that imports Tatu's models and uses the configured database URL. Key changes:
- Import `Base` from `app.models` and all model modules so metadata is populated
- Import `settings` from `app.config` for the database URL
- Use `run_async_migrations()` with `create_async_engine`

```python
# backend/alembic/env.py
import asyncio
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

from app.config import settings
from app.models import Base
import app.models.event  # noqa: F401
import app.models.hook  # noqa: F401
import app.models.api_key  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations():
    connectable = create_async_engine(settings.database_url, poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online():
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

- [ ] **Step 3: Update `backend/alembic.ini`**

Set `sqlalchemy.url` to empty (we use the app's config instead):

Change the line `sqlalchemy.url = driver://user:pass@localhost/dbname` to `sqlalchemy.url =`

- [ ] **Step 4: Generate initial migration**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret alembic revision --autogenerate -m "initial schema"
```

Expected: Creates a migration file in `backend/alembic/versions/`

- [ ] **Step 5: Run the migration**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret alembic upgrade head
```

Expected: Creates `tatu.db` with events, hooks, and api_keys tables

- [ ] **Step 6: Verify tables exist**

```bash
cd backend && python3 -c "import sqlite3; conn = sqlite3.connect('tatu.db'); print([t[0] for t in conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()])"
```

Expected: `['alembic_version', 'events', 'hooks', 'api_keys']`

- [ ] **Step 7: Commit**

```bash
git add backend/alembic/ backend/alembic.ini
git commit -m "feat: add Alembic migrations with initial schema"
```

---

### Task 5: Pydantic schemas

**Files:**
- Create: `backend/app/schemas/__init__.py`
- Create: `backend/app/schemas/event.py`
- Create: `backend/app/schemas/hook.py`
- Create: `backend/app/schemas/auth.py`
- Create: `backend/app/schemas/stats.py`
- Create: `backend/tests/test_schemas.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_schemas.py
import pytest
from pydantic import ValidationError
from app.schemas.event import EventCreate, EventResponse
from app.schemas.auth import LoginRequest, ApiKeyCreate, ApiKeyResponse
from app.schemas.stats import OverviewStats, TimelineBucket, PaginatedResponse


def test_event_create_valid():
    event = EventCreate(
        hook_name="Secrets Leak Prevention",
        hook_event="PreToolUse",
        severity="critical",
        status="blocked",
        message="AWS key detected",
        developer="carlos.m",
        repository="payments-api",
        session_id="sess-123",
        tool_name="Write",
    )
    assert event.hook_name == "Secrets Leak Prevention"


def test_event_create_invalid_severity():
    with pytest.raises(ValidationError):
        EventCreate(
            hook_name="Test",
            hook_event="PreToolUse",
            severity="invalid",
            status="blocked",
            message="test",
            developer="dev",
            repository="repo",
            session_id="sess",
        )


def test_event_create_nullable_tool_name():
    event = EventCreate(
        hook_name="Env Hardening",
        hook_event="SessionStart",
        severity="info",
        status="allowed",
        message="Env check passed",
        developer="dev",
        repository="repo",
        session_id="sess",
        tool_name=None,
    )
    assert event.tool_name is None


def test_login_request():
    req = LoginRequest(password="mypassword")
    assert req.password == "mypassword"


def test_api_key_create():
    key = ApiKeyCreate(label="production-hooks")
    assert key.label == "production-hooks"


def test_overview_stats():
    stats = OverviewStats(
        total_events=1000,
        total_blocks=50,
        active_sessions=5,
        secrets_caught=12,
        block_rate=5.0,
    )
    assert stats.total_events == 1000


def test_paginated_response():
    resp = PaginatedResponse(
        items=[],
        total=100,
        page=1,
        per_page=50,
        pages=2,
    )
    assert resp.pages == 2
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_schemas.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `backend/app/schemas/__init__.py`**

Empty file.

- [ ] **Step 4: Write `backend/app/schemas/event.py`**

```python
# backend/app/schemas/event.py
from datetime import datetime
from uuid import UUID
from typing import Any, Literal
from pydantic import BaseModel


class EventCreate(BaseModel):
    hook_name: str
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ]
    severity: Literal["critical", "warning", "info"]
    status: Literal["blocked", "warning", "allowed", "clean"]
    message: str
    developer: str
    repository: str
    session_id: str
    tool_name: str | None = None
    metadata: dict[str, Any] = {}


class EventResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    timestamp: datetime
    hook_name: str
    hook_event: str
    severity: str
    status: str
    message: str
    developer: str
    repository: str
    session_id: str
    tool_name: str | None
    metadata_: dict[str, Any]
```

- [ ] **Step 5: Write `backend/app/schemas/auth.py`**

```python
# backend/app/schemas/auth.py
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class LoginRequest(BaseModel):
    password: str


class LoginResponse(BaseModel):
    message: str = "authenticated"


class ApiKeyCreate(BaseModel):
    label: str


class ApiKeyCreateResponse(BaseModel):
    id: UUID
    label: str
    api_key: str  # plaintext, shown only once


class ApiKeyResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    label: str
    created_at: datetime
    last_used_at: datetime | None
    active: bool
```

- [ ] **Step 6: Write `backend/app/schemas/hook.py`**

```python
# backend/app/schemas/hook.py
from uuid import UUID
from pydantic import BaseModel


class HookResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    name: str
    category: str
    hook_event: str
    matcher: str
    enabled: bool
    compliance_mappings: list[str]


class HookWithStats(HookResponse):
    triggers: int = 0
    blocks: int = 0
    block_rate: str = "0%"
```

- [ ] **Step 7: Write `backend/app/schemas/stats.py`**

```python
# backend/app/schemas/stats.py
from typing import Any
from pydantic import BaseModel


class OverviewStats(BaseModel):
    total_events: int
    total_blocks: int
    active_sessions: int
    secrets_caught: int
    block_rate: float


class TimelineBucket(BaseModel):
    hour: str
    events: int
    blocks: int


class DeveloperStats(BaseModel):
    name: str
    sessions: int
    blocks: int
    risk: str  # "high" or "low"


class ComplianceFramework(BaseModel):
    framework: str
    controls: int
    covered: int
    status: str
    percentage: int


class ComplianceMapping(BaseModel):
    hook: str
    maps: str


class ComplianceResponse(BaseModel):
    frameworks: list[ComplianceFramework]
    mappings: list[ComplianceMapping]


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    per_page: int
    pages: int
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_schemas.py -v
```

Expected: All 7 tests PASS

- [ ] **Step 9: Commit**

```bash
git add backend/app/schemas/ backend/tests/test_schemas.py
git commit -m "feat: add Pydantic schemas for events, auth, hooks, and stats"
```

---

### Task 6: FastAPI app skeleton with health check

**Files:**
- Create: `backend/app/main.py`
- Create: `backend/tests/test_health.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_health.py
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_health.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/main.py`**

```python
# backend/app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import settings
from app.database import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


app = FastAPI(
    title="Tatu — DevSecOps Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
async def health_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception:
        return {"status": "degraded", "db": "disconnected"}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_health.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/main.py backend/tests/test_health.py
git commit -m "feat: add FastAPI app skeleton with health check endpoint"
```

---

## Chunk 2: Backend Auth & Event Ingestion

### Task 7: Auth module (API key + dashboard password)

**Files:**
- Create: `backend/app/auth.py`
- Create: `backend/tests/test_auth.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_auth.py
import pytest
from app.auth import hash_api_key, verify_api_key, create_signed_cookie, verify_signed_cookie


def test_hash_and_verify_api_key():
    raw_key = "tatu_abc123def456"
    hashed = hash_api_key(raw_key)
    assert hashed != raw_key
    assert verify_api_key(raw_key, hashed) is True
    assert verify_api_key("wrong_key", hashed) is False


def test_create_and_verify_signed_cookie():
    cookie_value = create_signed_cookie()
    assert verify_signed_cookie(cookie_value) is True
    assert verify_signed_cookie("tampered_value") is False
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_auth.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/auth.py`**

```python
# backend/app/auth.py
import hashlib
import hmac
import secrets
import time

from fastapi import Depends, HTTPException, Request, WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db
from app.models.api_key import ApiKey

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

COOKIE_NAME = "tatu_session"
COOKIE_MAX_AGE = 86400  # 24 hours

_serializer = URLSafeTimedSerializer(settings.secret_key)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def verify_api_key(raw_key: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key), hashed)


def generate_api_key() -> str:
    return f"tatu_{secrets.token_urlsafe(32)}"


def create_signed_cookie() -> str:
    return _serializer.dumps({"authenticated": True, "t": int(time.time())})


def verify_signed_cookie(cookie_value: str) -> bool:
    try:
        _serializer.loads(cookie_value, max_age=COOKIE_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


async def require_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ApiKey:
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_hash = hash_api_key(key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return api_key


async def require_dashboard_auth(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie or not verify_signed_cookie(cookie):
        raise HTTPException(status_code=401, detail="Not authenticated")


async def require_ws_auth(websocket: WebSocket):
    cookie = websocket.cookies.get(COOKIE_NAME)
    if not cookie or not verify_signed_cookie(cookie):
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Not authenticated")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_auth.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/auth.py backend/tests/test_auth.py
git commit -m "feat: add auth module with API key hashing and signed cookies"
```

---

### Task 8: Auth router (login + API key management)

**Files:**
- Create: `backend/app/routers/__init__.py`
- Create: `backend/app/routers/auth.py`
- Create: `backend/tests/test_router_auth.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_router_auth.py
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.database import get_db


@pytest_asyncio.fixture
async def db_override():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_override):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={"password": "testpass"})
    assert resp.status_code == 200
    assert "tatu_session" in resp.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={"password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_key_lifecycle(client: AsyncClient):
    # Login first
    login_resp = await client.post("/api/v1/auth/login", json={"password": "testpass"})
    cookies = login_resp.cookies

    # Create API key
    create_resp = await client.post(
        "/api/v1/auth/api-keys",
        json={"label": "test-key"},
        cookies=cookies,
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    assert data["label"] == "test-key"
    assert data["api_key"].startswith("tatu_")
    key_id = data["id"]

    # List API keys
    list_resp = await client.get("/api/v1/auth/api-keys", cookies=cookies)
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert len(keys) == 1
    assert "api_key" not in keys[0]  # secret not exposed

    # Revoke
    del_resp = await client.delete(f"/api/v1/auth/api-keys/{key_id}", cookies=cookies)
    assert del_resp.status_code == 204
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_auth.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/routers/__init__.py`**

Empty file.

- [ ] **Step 4: Write `backend/app/routers/auth.py`**

```python
# backend/app/routers/auth.py
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.auth import (
    hash_api_key, generate_api_key, create_signed_cookie,
    require_dashboard_auth, COOKIE_NAME, COOKIE_MAX_AGE,
)
from app.config import settings
from app.database import get_db
from app.models.api_key import ApiKey
from app.schemas.auth import (
    LoginRequest, LoginResponse, ApiKeyCreate,
    ApiKeyCreateResponse, ApiKeyResponse,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, response: Response):
    if body.password != settings.dashboard_password:
        raise HTTPException(status_code=401, detail="Invalid password")
    cookie_value = create_signed_cookie()
    response.set_cookie(
        key=COOKIE_NAME,
        value=cookie_value,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return LoginResponse()


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201,
             dependencies=[Depends(require_dashboard_auth)])
async def create_api_key(body: ApiKeyCreate, db: AsyncSession = Depends(get_db)):
    raw_key = generate_api_key()
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash=hash_api_key(raw_key),
        label=body.label,
        created_at=datetime.now(timezone.utc),
        active=True,
    )
    db.add(api_key)
    await db.commit()
    return ApiKeyCreateResponse(id=api_key.id, label=api_key.label, api_key=raw_key)


@router.get("/api-keys", response_model=list[ApiKeyResponse],
            dependencies=[Depends(require_dashboard_auth)])
async def list_api_keys(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.active == True))
    return result.scalars().all()


@router.delete("/api-keys/{key_id}", status_code=204,
               dependencies=[Depends(require_dashboard_auth)])
async def revoke_api_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.active = False
    await db.commit()
```

- [ ] **Step 5: Register router in `backend/app/main.py`**

Add to `main.py` after CORS middleware:

```python
from app.routers import auth as auth_router

app.include_router(auth_router.router)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_auth.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/routers/ backend/tests/test_router_auth.py backend/app/main.py
git commit -m "feat: add auth router with login and API key management"
```

---

### Task 9: WebSocket manager

**Files:**
- Create: `backend/app/services/__init__.py`
- Create: `backend/app/services/websocket_manager.py`
- Create: `backend/tests/test_websocket_manager.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_websocket_manager.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.websocket_manager import WebSocketManager


@pytest.mark.asyncio
async def test_connect_and_broadcast():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()

    await manager.connect(ws)
    assert len(manager.active_connections) == 1

    await manager.broadcast({"type": "event", "data": "test"})
    ws.send_json.assert_called_once_with({"type": "event", "data": "test"})


@pytest.mark.asyncio
async def test_disconnect():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()

    await manager.connect(ws)
    manager.disconnect(ws)
    assert len(manager.active_connections) == 0


@pytest.mark.asyncio
async def test_broadcast_removes_dead_connections():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock(side_effect=Exception("connection closed"))

    await manager.connect(ws)
    await manager.broadcast({"type": "test"})
    assert len(manager.active_connections) == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_websocket_manager.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/services/__init__.py`**

Empty file.

- [ ] **Step 4: Write `backend/app/services/websocket_manager.py`**

```python
# backend/app/services/websocket_manager.py
from fastapi import WebSocket


class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections = [
            ws for ws in self.active_connections if ws is not websocket
        ]

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WebSocketManager()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_websocket_manager.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/ backend/tests/test_websocket_manager.py
git commit -m "feat: add WebSocket manager for real-time event broadcasting"
```

---

### Task 10: Event ingestion endpoint + WebSocket route

**Files:**
- Create: `backend/app/routers/events.py`
- Create: `backend/tests/test_router_events.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_router_events.py
import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.api_key import ApiKey
from app.auth import hash_api_key
from app.database import get_db


@pytest_asyncio.fixture
async def db_setup():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed an API key
    async with session_factory() as session:
        api_key = ApiKey(
            id=uuid.uuid4(),
            key_hash=hash_api_key("tatu_testkey123"),
            label="test",
            created_at=datetime.now(timezone.utc),
            active=True,
        )
        session.add(api_key)
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield session_factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_setup):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_ingest_event(client: AsyncClient):
    resp = await client.post(
        "/api/v1/events",
        json={
            "hook_name": "Secrets Leak Prevention",
            "hook_event": "PreToolUse",
            "severity": "critical",
            "status": "blocked",
            "message": "AWS key detected in config.py",
            "developer": "carlos.m",
            "repository": "payments-api",
            "session_id": "sess-123",
            "tool_name": "Write",
        },
        headers={"X-API-Key": "tatu_testkey123"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["hook_name"] == "Secrets Leak Prevention"
    assert "id" in data


@pytest.mark.asyncio
async def test_ingest_event_no_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/events",
        json={
            "hook_name": "Test",
            "hook_event": "PreToolUse",
            "severity": "info",
            "status": "allowed",
            "message": "test",
            "developer": "dev",
            "repository": "repo",
            "session_id": "sess",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_event_invalid_api_key(client: AsyncClient):
    resp = await client.post(
        "/api/v1/events",
        json={
            "hook_name": "Test",
            "hook_event": "PreToolUse",
            "severity": "info",
            "status": "allowed",
            "message": "test",
            "developer": "dev",
            "repository": "repo",
            "session_id": "sess",
        },
        headers={"X-API-Key": "tatu_wrong_key"},
    )
    assert resp.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_events.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/routers/events.py`**

```python
# backend/app/routers/events.py
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_api_key, require_ws_auth
from app.database import get_db
from app.models.api_key import ApiKey
from app.models.event import Event
from app.schemas.event import EventCreate, EventResponse
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.post("/events", response_model=EventResponse, status_code=201)
async def ingest_event(
    body: EventCreate,
    api_key: ApiKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name=body.hook_name,
        hook_event=body.hook_event,
        severity=body.severity,
        status=body.status,
        message=body.message,
        developer=body.developer,
        repository=body.repository,
        session_id=body.session_id,
        tool_name=body.tool_name,
        metadata_=body.metadata,
    )
    db.add(event)

    # Update API key last_used_at
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    # Broadcast to WebSocket clients
    await ws_manager.broadcast({
        "type": "new_event",
        "event": {
            "id": str(event.id),
            "timestamp": event.timestamp.isoformat(),
            "hook_name": event.hook_name,
            "hook_event": event.hook_event,
            "severity": event.severity,
            "status": event.status,
            "message": event.message,
            "developer": event.developer,
            "repository": event.repository,
            "session_id": event.session_id,
            "tool_name": event.tool_name,
        },
    })

    return event


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await require_ws_auth(websocket)
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
```

- [ ] **Step 4: Register router in `backend/app/main.py`**

Add to `main.py`:

```python
from app.routers import events as events_router

app.include_router(events_router.router)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_events.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/routers/events.py backend/tests/test_router_events.py backend/app/main.py
git commit -m "feat: add event ingestion endpoint with API key auth and WebSocket broadcast"
```

---

## Chunk 3: Backend Dashboard Query Endpoints

### Task 11: Overview endpoints (stats + timeline)

**Files:**
- Create: `backend/app/routers/overview.py`
- Create: `backend/app/services/stats_service.py`
- Create: `backend/tests/test_router_overview.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_router_overview.py
import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.event import Event
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME


@pytest_asyncio.fixture
async def seeded_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed events
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        for i in range(10):
            session.add(Event(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i * 5),
                hook_name="Secrets Leak Prevention" if i < 3 else "Cmd Blocker",
                hook_event="PreToolUse",
                severity="critical" if i < 3 else "warning",
                status="blocked" if i < 5 else "allowed",
                message=f"Test event {i}",
                developer=f"dev{i % 3}",
                repository="test-repo",
                session_id=f"sess-{i % 2}",
                tool_name="Bash",
            ))
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def authed_client(seeded_db):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie()
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_overview_stats(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/overview/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 10
    assert data["total_blocks"] == 5
    assert data["active_sessions"] == 2
    assert data["secrets_caught"] == 3


@pytest.mark.asyncio
async def test_overview_stats_requires_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/overview/stats")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_overview_timeline(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/overview/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert all("hour" in b and "events" in b and "blocks" in b for b in data)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_overview.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/services/stats_service.py`**

```python
# backend/app/services/stats_service.py
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func, case, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event


def _period_to_delta(period: str) -> timedelta:
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    return mapping.get(period, timedelta(hours=24))


def _period_start(period: str) -> datetime:
    return datetime.now(timezone.utc) - _period_to_delta(period)


async def get_overview_stats(db: AsyncSession, period: str = "24h") -> dict:
    start = _period_start(period)

    result = await db.execute(
        select(
            func.count(Event.id).label("total_events"),
            func.sum(case((Event.status == "blocked", 1), else_=0)).label("total_blocks"),
            func.sum(case(
                (Event.hook_name == "Secrets Leak Prevention", 1), else_=0
            )).label("secrets_caught"),
        ).where(Event.timestamp >= start)
    )
    row = result.one()
    total_events = row.total_events or 0
    total_blocks = row.total_blocks or 0
    secrets_caught = row.secrets_caught or 0

    # Active sessions: distinct session_ids with events in last 30 minutes
    thirty_min_ago = datetime.now(timezone.utc) - timedelta(minutes=30)
    sessions_result = await db.execute(
        select(func.count(distinct(Event.session_id))).where(
            Event.timestamp >= thirty_min_ago
        )
    )
    active_sessions = sessions_result.scalar() or 0

    block_rate = (total_blocks / total_events * 100) if total_events > 0 else 0.0

    return {
        "total_events": total_events,
        "total_blocks": total_blocks,
        "active_sessions": active_sessions,
        "secrets_caught": secrets_caught,
        "block_rate": round(block_rate, 1),
    }


async def get_timeline(db: AsyncSession, period: str = "24h") -> list[dict]:
    start = _period_start(period)

    result = await db.execute(
        select(
            func.strftime("%H", Event.timestamp).label("hour"),
            func.count(Event.id).label("events"),
            func.sum(case((Event.status == "blocked", 1), else_=0)).label("blocks"),
        )
        .where(Event.timestamp >= start)
        .group_by("hour")
        .order_by("hour")
    )

    return [
        {"hour": row.hour, "events": row.events, "blocks": row.blocks or 0}
        for row in result.all()
    ]
```

- [ ] **Step 4: Write `backend/app/routers/overview.py`**

```python
# backend/app/routers/overview.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.schemas.stats import OverviewStats, TimelineBucket
from app.services.stats_service import get_overview_stats, get_timeline

router = APIRouter(
    prefix="/api/v1/overview",
    tags=["overview"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/stats", response_model=OverviewStats)
async def overview_stats(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    return await get_overview_stats(db, period)


@router.get("/timeline", response_model=list[TimelineBucket])
async def overview_timeline(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    return await get_timeline(db, period)
```

- [ ] **Step 5: Register router in `backend/app/main.py`**

Add:

```python
from app.routers import overview as overview_router

app.include_router(overview_router.router)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_overview.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/routers/overview.py backend/app/services/stats_service.py backend/tests/test_router_overview.py backend/app/main.py
git commit -m "feat: add overview endpoints (stats + timeline)"
```

---

### Task 12: Alerts endpoint (paginated + filtered)

**Files:**
- Create: `backend/app/routers/alerts.py`
- Create: `backend/app/services/event_service.py`
- Create: `backend/tests/test_router_alerts.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_router_alerts.py
import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.event import Event
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME


@pytest_asyncio.fixture
async def seeded_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        for i in range(60):
            session.add(Event(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i),
                hook_name="Secrets Leak Prevention" if i % 2 == 0 else "Cmd Blocker",
                hook_event="PreToolUse",
                severity="critical" if i % 3 == 0 else "warning",
                status="blocked" if i % 2 == 0 else "allowed",
                message=f"Test event {i}",
                developer=f"dev{i % 3}",
                repository="test-repo",
                session_id=f"sess-{i}",
                tool_name="Bash",
            ))
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def authed_client(seeded_db):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie()
    async with AsyncClient(transport=transport, base_url="http://test", cookies={COOKIE_NAME: cookie}) as c:
        yield c


@pytest.mark.asyncio
async def test_alerts_default_pagination(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["per_page"] == 50
    assert data["page"] == 1
    assert data["total"] == 60
    assert data["pages"] == 2
    assert len(data["items"]) == 50


@pytest.mark.asyncio
async def test_alerts_page_2(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?page=2")
    data = resp.json()
    assert len(data["items"]) == 10


@pytest.mark.asyncio
async def test_alerts_filter_severity(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?severity=critical")
    data = resp.json()
    assert all(item["severity"] == "critical" for item in data["items"])


@pytest.mark.asyncio
async def test_alerts_filter_hook(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?hook=Cmd+Blocker")
    data = resp.json()
    assert all(item["hook_name"] == "Cmd Blocker" for item in data["items"])
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_alerts.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/services/event_service.py`**

```python
# backend/app/services/event_service.py
from datetime import datetime, timezone, timedelta
import math
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event


def _period_start(period: str) -> datetime:
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    return datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))


async def get_alerts(
    db: AsyncSession,
    period: str = "24h",
    severity: str | None = None,
    hook: str | None = None,
    developer: str | None = None,
    status: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    per_page = min(per_page, 200)
    start = _period_start(period)

    query = select(Event).where(Event.timestamp >= start)
    count_query = select(func.count(Event.id)).where(Event.timestamp >= start)

    if severity:
        query = query.where(Event.severity == severity)
        count_query = count_query.where(Event.severity == severity)
    if hook:
        query = query.where(Event.hook_name == hook)
        count_query = count_query.where(Event.hook_name == hook)
    if developer:
        query = query.where(Event.developer == developer)
        count_query = count_query.where(Event.developer == developer)
    if status:
        query = query.where(Event.status == status)
        count_query = count_query.where(Event.status == status)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(Event.timestamp.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    items = result.scalars().all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": math.ceil(total / per_page) if per_page > 0 else 0,
    }
```

- [ ] **Step 4: Write `backend/app/routers/alerts.py`**

```python
# backend/app/routers/alerts.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.schemas.event import EventResponse
from app.schemas.stats import PaginatedResponse
from app.services.event_service import get_alerts

router = APIRouter(
    prefix="/api/v1",
    tags=["alerts"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/alerts", response_model=PaginatedResponse)
async def list_alerts(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    severity: str | None = Query(None),
    hook: str | None = Query(None),
    developer: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    return await get_alerts(db, period, severity, hook, developer, status, page, per_page)
```

- [ ] **Step 5: Register router in `backend/app/main.py`**

Add:

```python
from app.routers import alerts as alerts_router

app.include_router(alerts_router.router)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_alerts.py -v
```

Expected: All 4 tests PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/routers/alerts.py backend/app/services/event_service.py backend/tests/test_router_alerts.py backend/app/main.py
git commit -m "feat: add alerts endpoint with pagination and filters"
```

---

### Task 13: Hooks, Compliance, Developers, and Audit endpoints

**Files:**
- Create: `backend/app/routers/hooks.py`
- Create: `backend/app/routers/compliance.py`
- Create: `backend/app/routers/developers.py`
- Create: `backend/app/routers/audit.py`
- Create: `backend/tests/test_router_dashboard.py`
- Create: `backend/app/seed.py`

This task adds the remaining 4 dashboard query endpoints and a seed script for hooks data.

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_router_dashboard.py
import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.event import Event
from app.models.hook import Hook
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME


@pytest_asyncio.fixture
async def seeded_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        # Seed hooks
        session.add(Hook(
            id=uuid.uuid4(), name="Secrets Leak Prevention",
            category="offensive_guardrails", hook_event="PreToolUse",
            matcher="Bash|Write|Edit", enabled=True,
            compliance_mappings=["SOC2 CC6.1", "LGPD Art. 46", "ISO 27001 A.9.4"],
        ))
        session.add(Hook(
            id=uuid.uuid4(), name="Destructive Cmd Blocker",
            category="offensive_guardrails", hook_event="PreToolUse",
            matcher="Bash", enabled=True,
            compliance_mappings=["CPS234 Logging", "ISO 27001 A.12.4"],
        ))

        # Seed events
        for i in range(20):
            session.add(Event(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i * 2),
                hook_name="Secrets Leak Prevention" if i % 2 == 0 else "Destructive Cmd Blocker",
                hook_event="PreToolUse",
                severity="critical" if i < 5 else "info",
                status="blocked" if i < 8 else "allowed",
                message=f"Event {i}",
                developer=f"dev{i % 3}",
                repository="test-repo",
                session_id=f"sess-{i % 4}",
                tool_name="Bash",
            ))
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def authed_client(seeded_db):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie()
    async with AsyncClient(transport=transport, base_url="http://test", cookies={COOKIE_NAME: cookie}) as c:
        yield c


@pytest.mark.asyncio
async def test_hooks_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/hooks")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert all("triggers" in h and "blocks" in h and "block_rate" in h for h in data)


@pytest.mark.asyncio
async def test_compliance_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/compliance")
    assert resp.status_code == 200
    data = resp.json()
    assert "frameworks" in data
    assert "mappings" in data
    assert len(data["frameworks"]) == 4  # SOC2, LGPD, CPS234, ISO 27001


@pytest.mark.asyncio
async def test_developers_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/developers")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3  # dev0, dev1, dev2
    assert all("name" in d and "sessions" in d and "blocks" in d and "risk" in d for d in data)


@pytest.mark.asyncio
async def test_audit_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 20
    assert len(data["items"]) == 20


@pytest.mark.asyncio
async def test_audit_csv_export(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/audit?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.strip().split("\n")
    assert len(lines) == 21  # header + 20 rows
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_dashboard.py -v
```

Expected: FAIL

- [ ] **Step 3: Write `backend/app/routers/hooks.py`**

```python
# backend/app/routers/hooks.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from datetime import datetime, timezone, timedelta

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.hook import Hook
from app.models.event import Event
from app.schemas.hook import HookWithStats

router = APIRouter(
    prefix="/api/v1",
    tags=["hooks"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/hooks", response_model=list[HookWithStats])
async def list_hooks(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))

    hooks_result = await db.execute(select(Hook))
    hooks = hooks_result.scalars().all()

    result = []
    for hook in hooks:
        stats = await db.execute(
            select(
                func.count(Event.id).label("triggers"),
                func.sum(case((Event.status == "blocked", 1), else_=0)).label("blocks"),
            ).where(Event.hook_name == hook.name, Event.timestamp >= start)
        )
        row = stats.one()
        triggers = row.triggers or 0
        blocks = row.blocks or 0
        rate = f"{(blocks / triggers * 100):.1f}%" if triggers > 0 else "0%"

        result.append(HookWithStats(
            id=hook.id, name=hook.name, category=hook.category,
            hook_event=hook.hook_event, matcher=hook.matcher,
            enabled=hook.enabled, compliance_mappings=hook.compliance_mappings,
            triggers=triggers, blocks=blocks, block_rate=rate,
        ))

    return result
```

- [ ] **Step 4: Write `backend/app/routers/compliance.py`**

```python
# backend/app/routers/compliance.py
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.hook import Hook
from app.schemas.stats import ComplianceResponse, ComplianceFramework, ComplianceMapping

router = APIRouter(
    prefix="/api/v1",
    tags=["compliance"],
    dependencies=[Depends(require_dashboard_auth)],
)

FRAMEWORK_TOTALS = {"SOC2": 14, "LGPD": 8, "CPS234": 12, "ISO 27001": 18}


@router.get("/compliance", response_model=ComplianceResponse)
async def get_compliance(db: AsyncSession = Depends(get_db)):
    hooks_result = await db.execute(select(Hook).where(Hook.enabled == True))
    hooks = hooks_result.scalars().all()

    # Count how many enabled hooks map to each framework
    framework_coverage: dict[str, set[str]] = {fw: set() for fw in FRAMEWORK_TOTALS}
    mappings: list[ComplianceMapping] = []

    for hook in hooks:
        hook_frameworks = []
        for mapping in hook.compliance_mappings:
            for fw in FRAMEWORK_TOTALS:
                if mapping.startswith(fw) or (fw == "ISO 27001" and mapping.startswith("ISO")):
                    framework_coverage[fw].add(mapping)
                    hook_frameworks.append(mapping)
        if hook_frameworks:
            mappings.append(ComplianceMapping(
                hook=hook.name,
                maps=", ".join(hook.compliance_mappings),
            ))

    frameworks = []
    for fw, total in FRAMEWORK_TOTALS.items():
        covered = len(framework_coverage[fw])
        pct = round((covered / total) * 100) if total > 0 else 0
        status = "compliant" if pct >= 90 else "partial" if pct >= 50 else "low"
        frameworks.append(ComplianceFramework(
            framework=fw, controls=total, covered=covered,
            status=status, percentage=pct,
        ))

    return ComplianceResponse(frameworks=frameworks, mappings=mappings)
```

- [ ] **Step 5: Write `backend/app/routers/developers.py`**

```python
# backend/app/routers/developers.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, distinct
from datetime import datetime, timezone, timedelta

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.event import Event
from app.schemas.stats import DeveloperStats

router = APIRouter(
    prefix="/api/v1",
    tags=["developers"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/developers", response_model=list[DeveloperStats])
async def list_developers(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))

    result = await db.execute(
        select(
            Event.developer,
            func.count(distinct(Event.session_id)).label("sessions"),
            func.sum(case((Event.status == "blocked", 1), else_=0)).label("blocks"),
        )
        .where(Event.timestamp >= start)
        .group_by(Event.developer)
        .order_by(func.sum(case((Event.status == "blocked", 1), else_=0)).desc())
    )

    return [
        DeveloperStats(
            name=row.developer,
            sessions=row.sessions,
            blocks=row.blocks or 0,
            risk="high" if (row.blocks or 0) > 5 else "low",
        )
        for row in result.all()
    ]
```

- [ ] **Step 6: Write `backend/app/routers/audit.py`**

```python
# backend/app/routers/audit.py
import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.schemas.stats import PaginatedResponse
from app.services.event_service import get_alerts

router = APIRouter(
    prefix="/api/v1",
    tags=["audit"],
    dependencies=[Depends(require_dashboard_auth)],
)

STATUS_LABELS = {"blocked": "DENY", "warning": "WARN", "allowed": "ALLOW", "clean": "PASS"}


@router.get("/audit")
async def audit_log(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    format: str | None = Query(None, pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
):
    # For export, get all records (no pagination)
    if format in ("csv", "json"):
        data = await get_alerts(db, period, page=1, per_page=10000)
    else:
        data = await get_alerts(db, period, page=page, per_page=per_page)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "developer", "hook", "event_detail", "result"])
        for event in data["items"]:
            writer.writerow([
                event.timestamp.isoformat(),
                event.developer,
                event.hook_name,
                event.message,
                STATUS_LABELS.get(event.status, event.status),
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=tatu-audit.csv"},
        )

    if format == "json":
        items = [
            {
                "timestamp": event.timestamp.isoformat(),
                "developer": event.developer,
                "hook": event.hook_name,
                "event_detail": event.message,
                "result": STATUS_LABELS.get(event.status, event.status),
            }
            for event in data["items"]
        ]
        return items

    return data
```

- [ ] **Step 7: Register all routers in `backend/app/main.py`**

Add:

```python
from app.routers import hooks as hooks_router
from app.routers import compliance as compliance_router
from app.routers import developers as developers_router
from app.routers import audit as audit_router

app.include_router(hooks_router.router)
app.include_router(compliance_router.router)
app.include_router(developers_router.router)
app.include_router(audit_router.router)
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/test_router_dashboard.py -v
```

Expected: All 5 tests PASS

- [ ] **Step 9: Commit**

```bash
git add backend/app/routers/ backend/tests/test_router_dashboard.py backend/app/main.py
git commit -m "feat: add hooks, compliance, developers, and audit endpoints"
```

---

### Task 14: Seed data script

**Files:**
- Create: `backend/app/seed.py`

- [ ] **Step 1: Write `backend/app/seed.py`**

A script that populates the hooks table with the 15 hooks from the spec document, including their compliance mappings. Run with `python -m app.seed`.

```python
# backend/app/seed.py
"""Seed the database with default hook configurations from the spec."""
import asyncio
import uuid
from sqlalchemy import select
from app.database import engine, async_session
from app.models import Base
from app.models.hook import Hook

HOOKS = [
    {"name": "Destructive Command Blocker", "category": "offensive_guardrails", "hook_event": "PreToolUse", "matcher": "Bash", "compliance_mappings": ["CPS234 Op. Risk", "ISO 27001 A.12.4"]},
    {"name": "Secrets Leak Prevention", "category": "offensive_guardrails", "hook_event": "PreToolUse", "matcher": "Bash|Write|Edit", "compliance_mappings": ["SOC2 CC6.1", "LGPD Art. 46", "ISO 27001 A.9.4"]},
    {"name": "Network Scope Enforcer", "category": "offensive_guardrails", "hook_event": "PreToolUse", "matcher": "Bash", "compliance_mappings": ["ISO 27001 A.18"]},
    {"name": "Protected File Guardian", "category": "offensive_guardrails", "hook_event": "PreToolUse", "matcher": "Write|Edit|MultiEdit", "compliance_mappings": ["SOC2 CC6.1", "ISO 27001 A.9.4"]},
    {"name": "Auto SAST Scanner", "category": "secure_sdlc", "hook_event": "PostToolUse", "matcher": "Write|Edit|MultiEdit", "compliance_mappings": ["SOC2 CC8.1", "ISO 27001 A.14.2"]},
    {"name": "Dependency Vuln Check", "category": "secure_sdlc", "hook_event": "PostToolUse", "matcher": "Bash", "compliance_mappings": ["SOC2 CC7.1", "ISO 27001 A.12.6"]},
    {"name": "LGPD PII Detector", "category": "secure_sdlc", "hook_event": "PreToolUse", "matcher": "Write|Edit", "compliance_mappings": ["LGPD Art. 37", "LGPD Art. 46", "SOC2 CC6.5", "ISO 27001 A.18.1"]},
    {"name": "Security Unit Test Enforcer", "category": "secure_sdlc", "hook_event": "Stop", "matcher": "", "compliance_mappings": ["SOC2 CC7.1", "ISO 27001 A.14.2"]},
    {"name": "Session Audit Logger", "category": "compliance_audit", "hook_event": "PostToolUse", "matcher": ".*", "compliance_mappings": ["SOC2 CC7.2", "CPS234 Logging", "ISO 27001 A.12.4", "LGPD Art. 37"]},
    {"name": "Transcript Backup", "category": "compliance_audit", "hook_event": "PreCompact", "matcher": "", "compliance_mappings": ["CPS234 Records", "SOC2 CC7.4", "LGPD Art. 37"]},
    {"name": "Change Classification", "category": "compliance_audit", "hook_event": "PostToolUse", "matcher": "Write|Edit|MultiEdit", "compliance_mappings": ["SOC2 CC8.1", "ISO 27001 A.12.1.2", "CPS234 Change Mgmt"]},
    {"name": "SIEM/SOAR Forwarder", "category": "compliance_audit", "hook_event": "PostToolUse", "matcher": "Bash", "compliance_mappings": ["SOC2 CC7.2", "ISO 27001 A.12.4"]},
    {"name": "Threat Intel Injector", "category": "incident_response", "hook_event": "SessionStart", "matcher": "", "compliance_mappings": ["SOC2 CC7.1", "ISO 27001 A.12.6"]},
    {"name": "Security Alert Notifier", "category": "incident_response", "hook_event": "Notification", "matcher": "", "compliance_mappings": ["SOC2 CC7.3", "ISO 27001 A.16.1"]},
    {"name": "Env Hardening Validator", "category": "incident_response", "hook_event": "SessionStart", "matcher": "", "compliance_mappings": ["CPS234 Asset Controls", "ISO 27001 A.6.2"]},
]


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        existing = await session.execute(select(Hook))
        if existing.scalars().first():
            print("Hooks already seeded, skipping.")
            return

        for h in HOOKS:
            session.add(Hook(id=uuid.uuid4(), enabled=True, **h))
        await session.commit()
        print(f"Seeded {len(HOOKS)} hooks.")


if __name__ == "__main__":
    asyncio.run(seed())
```

- [ ] **Step 2: Run the seed script**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m app.seed
```

Expected: `Seeded 15 hooks.`

- [ ] **Step 3: Commit**

```bash
git add backend/app/seed.py
git commit -m "feat: add seed script with 15 hook configurations from spec"
```

---

## Chunk 4: Frontend Foundation

### Task 15: Vite + React + Tailwind setup

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/tsconfig.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tailwind.config.ts`
- Create: `frontend/postcss.config.js`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/index.css`

- [ ] **Step 1: Scaffold with Vite**

```bash
cd /Users/julio/Workspace/tatush && npm create vite@latest frontend -- --template react-ts
```

- [ ] **Step 2: Install Tailwind and dependencies**

```bash
cd frontend && npm install && npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 3: Install additional dependencies**

```bash
cd frontend && npm install react-router-dom
```

- [ ] **Step 4: Configure `frontend/vite.config.ts`**

```typescript
// frontend/vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
```

- [ ] **Step 5: Configure `frontend/src/index.css`**

```css
/* frontend/src/index.css */
@import "tailwindcss";

@theme {
  --color-tatu-bg: #0A0E17;
  --color-tatu-surface: #111827;
  --color-tatu-surface-alt: #151D2E;
  --color-tatu-border: #1E293B;
  --color-tatu-border-hover: #334155;
  --color-tatu-text: #E2E8F0;
  --color-tatu-text-muted: #94A3B8;
  --color-tatu-text-dim: #64748B;
  --color-tatu-accent: #10B981;
  --color-tatu-accent-dim: #059669;
  --color-tatu-accent-glow: rgba(16, 185, 129, 0.15);
  --color-tatu-critical: #EF4444;
  --color-tatu-critical-dim: rgba(239, 68, 68, 0.15);
  --color-tatu-warn: #F59E0B;
  --color-tatu-warn-dim: rgba(245, 158, 11, 0.15);
  --color-tatu-info: #3B82F6;
  --color-tatu-info-dim: rgba(59, 130, 246, 0.15);

  --font-mono: "JetBrains Mono", "SF Mono", "Fira Code", ui-monospace, monospace;
}

body {
  font-family: var(--font-mono);
  background-color: var(--color-tatu-bg);
  color: var(--color-tatu-text);
  margin: 0;
}
```

- [ ] **Step 6: Update `frontend/index.html`**

Ensure the `<head>` includes JetBrains Mono from Google Fonts:

```html
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
```

- [ ] **Step 7: Verify dev server starts**

```bash
cd frontend && npm run dev
```

Expected: Vite dev server starts on http://localhost:5173

- [ ] **Step 8: Commit**

```bash
git add frontend/
git commit -m "feat: scaffold frontend with Vite, React, TypeScript, and Tailwind"
```

---

### Task 16: API client, types, and auth hook

**Files:**
- Create: `frontend/src/lib/types.ts`
- Create: `frontend/src/lib/api.ts`
- Create: `frontend/src/hooks/useAuth.ts`

- [ ] **Step 1: Write `frontend/src/lib/types.ts`**

```typescript
// frontend/src/lib/types.ts
export interface Event {
  id: string;
  timestamp: string;
  hook_name: string;
  hook_event: string;
  severity: "critical" | "warning" | "info";
  status: "blocked" | "warning" | "allowed" | "clean";
  message: string;
  developer: string;
  repository: string;
  session_id: string;
  tool_name: string | null;
  metadata_: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface OverviewStats {
  total_events: number;
  total_blocks: number;
  active_sessions: number;
  secrets_caught: number;
  block_rate: number;
}

export interface TimelineBucket {
  hour: string;
  events: number;
  blocks: number;
}

export interface HookWithStats {
  id: string;
  name: string;
  category: string;
  hook_event: string;
  matcher: string;
  enabled: boolean;
  compliance_mappings: string[];
  triggers: number;
  blocks: number;
  block_rate: string;
}

export interface DeveloperStats {
  name: string;
  sessions: number;
  blocks: number;
  risk: "high" | "low";
}

export interface ComplianceFramework {
  framework: string;
  controls: number;
  covered: number;
  status: string;
  percentage: number;
}

export interface ComplianceMapping {
  hook: string;
  maps: string;
}

export interface ComplianceResponse {
  frameworks: ComplianceFramework[];
  mappings: ComplianceMapping[];
}

export interface ApiKeyResponse {
  id: string;
  label: string;
  created_at: string;
  last_used_at: string | null;
  active: boolean;
}
```

- [ ] **Step 2: Write `frontend/src/lib/api.ts`**

```typescript
// frontend/src/lib/api.ts
const BASE = "/api/v1";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (resp.status === 401) {
    window.location.href = "/login";
    throw new Error("Not authenticated");
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

export const api = {
  login: (password: string) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ password }) }),

  getOverviewStats: (period = "24h") =>
    request(`/overview/stats?period=${period}`),

  getTimeline: (period = "24h") =>
    request(`/overview/timeline?period=${period}`),

  getAlerts: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams({ period: "24h", ...params }).toString();
    return request(`/alerts?${qs}`);
  },

  getHooks: (period = "24h") =>
    request(`/hooks?period=${period}`),

  getCompliance: () =>
    request("/compliance"),

  getDevelopers: (period = "24h") =>
    request(`/developers?period=${period}`),

  getAudit: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams({ period: "24h", ...params }).toString();
    return request(`/audit?${qs}`);
  },

  getAuditExportUrl: (format: "csv" | "json", period = "24h") =>
    `${BASE}/audit?format=${format}&period=${period}`,
};
```

- [ ] **Step 3: Write `frontend/src/hooks/useAuth.ts`**

```typescript
// frontend/src/hooks/useAuth.ts
import { useState, useCallback } from "react";
import { api } from "../lib/api";

export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (password: string) => {
    try {
      setError(null);
      await api.login(password);
      setIsAuthenticated(true);
    } catch (err) {
      setError("Invalid password");
      setIsAuthenticated(false);
    }
  }, []);

  const checkAuth = useCallback(async () => {
    try {
      await api.getOverviewStats();
      setIsAuthenticated(true);
    } catch {
      setIsAuthenticated(false);
    }
  }, []);

  return { isAuthenticated, error, login, checkAuth };
}
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/ frontend/src/hooks/
git commit -m "feat: add API client, TypeScript types, and auth hook"
```

---

### Task 17: Layout, routing, and login page

**Files:**
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/components/Sidebar.tsx`
- Create: `frontend/src/components/GridPattern.tsx`
- Create: `frontend/src/components/TatuLogo.tsx`
- Create: `frontend/src/pages/Login.tsx`

- [ ] **Step 1: Write `frontend/src/components/TatuLogo.tsx`**

Port the SVG logo from the prototype — the geometric hexagonal armadillo shell.

```tsx
// frontend/src/components/TatuLogo.tsx
export function TatuLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <path d="M20 4L34 12V28L20 36L6 28V12L20 4Z" stroke="#10B981" strokeWidth="1.5" fill="none" opacity="0.6" />
      <path d="M20 8L30 14V26L20 32L10 26V14L20 8Z" stroke="#10B981" strokeWidth="1.5" fill="rgba(16,185,129,0.15)" />
      <path d="M20 12L26 16V24L20 28L14 24V16L20 12Z" fill="#10B981" opacity="0.3" />
      <circle cx="20" cy="20" r="3" fill="#10B981" />
      <line x1="20" y1="8" x2="20" y2="12" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="10" y1="14" x2="14" y2="16" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="30" y1="14" x2="26" y2="16" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="10" y1="26" x2="14" y2="24" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="30" y1="26" x2="26" y2="24" stroke="#10B981" strokeWidth="1" opacity="0.5" />
      <line x1="20" y1="32" x2="20" y2="28" stroke="#10B981" strokeWidth="1" opacity="0.5" />
    </svg>
  );
}
```

- [ ] **Step 2: Write `frontend/src/components/GridPattern.tsx`**

```tsx
// frontend/src/components/GridPattern.tsx
export function GridPattern() {
  return (
    <div
      className="fixed inset-0 pointer-events-none z-0"
      style={{
        backgroundImage: `
          linear-gradient(rgba(30,41,59,0.25) 1px, transparent 1px),
          linear-gradient(90deg, rgba(30,41,59,0.25) 1px, transparent 1px)
        `,
        backgroundSize: "48px 48px",
      }}
    />
  );
}
```

- [ ] **Step 3: Write `frontend/src/components/Sidebar.tsx`**

```tsx
// frontend/src/components/Sidebar.tsx
import { NavLink } from "react-router-dom";
import { TatuLogo } from "./TatuLogo";

const NAV_ITEMS = [
  { to: "/", icon: "◆", label: "Overview" },
  { to: "/alerts", icon: "⚡", label: "Live Alerts" },
  { to: "/hooks", icon: "⬡", label: "Hooks" },
  { to: "/compliance", icon: "◎", label: "Compliance" },
  { to: "/developers", icon: "⧫", label: "Developers" },
  { to: "/audit", icon: "▤", label: "Audit Log" },
];

export function Sidebar() {
  return (
    <nav className="w-[220px] min-h-screen bg-tatu-surface border-r border-tatu-border p-5 flex flex-col gap-1 shrink-0 relative z-10">
      <div className="flex items-center gap-2.5 px-4 pb-5 border-b border-tatu-border mb-3">
        <TatuLogo size={32} />
        <div>
          <div className="text-base font-bold text-tatu-text tracking-widest">TATU</div>
          <div className="text-[8px] text-tatu-text-dim tracking-widest uppercase">DevSecOps Platform</div>
        </div>
      </div>
      {NAV_ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.to === "/"}
          className={({ isActive }) =>
            `flex items-center gap-2.5 w-full px-4 py-2.5 rounded-md text-xs tracking-wide transition-colors ${
              isActive
                ? "bg-tatu-accent-glow text-tatu-accent font-semibold"
                : "text-tatu-text-dim hover:text-tatu-text-muted"
            }`
          }
        >
          <span className="text-base w-5 text-center">{item.icon}</span>
          {item.label}
        </NavLink>
      ))}
      <div className="flex-1" />
      <div className="px-4 pt-3 border-t border-tatu-border mt-2">
        <div className="text-[10px] text-tatu-text-dim tracking-widest">ORGANIZATION</div>
        <div className="text-xs text-tatu-text mt-1">Laboratório Hacker</div>
      </div>
    </nav>
  );
}
```

- [ ] **Step 4: Write `frontend/src/pages/Login.tsx`**

```tsx
// frontend/src/pages/Login.tsx
import { useState, FormEvent } from "react";
import { TatuLogo } from "../components/TatuLogo";
import { GridPattern } from "../components/GridPattern";

interface LoginProps {
  onLogin: (password: string) => Promise<void>;
  error: string | null;
}

export function Login({ onLogin, error }: LoginProps) {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    await onLogin(password);
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-tatu-bg relative">
      <GridPattern />
      <form
        onSubmit={handleSubmit}
        className="relative z-10 bg-tatu-surface border border-tatu-border rounded-lg p-8 w-80 flex flex-col items-center gap-6"
      >
        <TatuLogo size={48} />
        <div className="text-center">
          <div className="text-xl font-bold tracking-widest text-tatu-text">TATU</div>
          <div className="text-[10px] text-tatu-text-dim tracking-widest uppercase mt-1">
            DevSecOps and GRC Platform for AI Development
          </div>
        </div>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Dashboard password"
          className="w-full px-4 py-2.5 rounded-md bg-tatu-surface-alt border border-tatu-border text-tatu-text text-sm placeholder:text-tatu-text-dim focus:outline-none focus:border-tatu-accent"
        />
        {error && (
          <div className="text-tatu-critical text-xs">{error}</div>
        )}
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 rounded-md bg-tatu-accent text-tatu-bg text-sm font-semibold hover:bg-tatu-accent-dim transition-colors disabled:opacity-50"
        >
          {loading ? "..." : "Enter"}
        </button>
      </form>
    </div>
  );
}
```

- [ ] **Step 5: Write `frontend/src/App.tsx`**

```tsx
// frontend/src/App.tsx
import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import { Sidebar } from "./components/Sidebar";
import { GridPattern } from "./components/GridPattern";
import { Login } from "./pages/Login";

function DashboardLayout() {
  return (
    <div className="flex min-h-screen bg-tatu-bg relative">
      <GridPattern />
      <Sidebar />
      <main className="flex-1 p-7 overflow-y-auto relative z-[1]">
        <Outlet />
      </main>
    </div>
  );
}

function Placeholder({ title }: { title: string }) {
  return (
    <div className="text-tatu-text-muted text-sm">
      <h1 className="text-xl font-bold text-tatu-text mb-2">{title}</h1>
      <p>Coming soon...</p>
    </div>
  );
}

export default function App() {
  const { isAuthenticated, error, login, checkAuth } = useAuth();

  useEffect(() => { checkAuth(); }, [checkAuth]);

  if (isAuthenticated === null) {
    return <div className="min-h-screen bg-tatu-bg" />;
  }

  if (!isAuthenticated) {
    return <Login onLogin={login} error={error} />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<DashboardLayout />}>
          <Route index element={<Placeholder title="Overview" />} />
          <Route path="alerts" element={<Placeholder title="Live Alerts" />} />
          <Route path="hooks" element={<Placeholder title="Hooks" />} />
          <Route path="compliance" element={<Placeholder title="Compliance" />} />
          <Route path="developers" element={<Placeholder title="Developers" />} />
          <Route path="audit" element={<Placeholder title="Audit Log" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
```

- [ ] **Step 6: Update `frontend/src/main.tsx`**

```tsx
// frontend/src/main.tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 7: Verify it compiles**

```bash
cd frontend && npm run build
```

Expected: Build succeeds with no errors.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/
git commit -m "feat: add layout, routing, sidebar, login page, and design system"
```

---

### Task 18: Shared UI components

**Files:**
- Create: `frontend/src/components/StatCard.tsx`
- Create: `frontend/src/components/SeverityBadge.tsx`
- Create: `frontend/src/components/StatusDot.tsx`
- Create: `frontend/src/components/Panel.tsx`
- Create: `frontend/src/components/TimelineChart.tsx`
- Create: `frontend/src/components/ComplianceGauge.tsx`
- Create: `frontend/src/components/PageHeader.tsx`

- [ ] **Step 1: Write all shared components**

These are direct ports from the React prototype, converted to Tailwind classes. Each is a small, focused file.

**`StatCard.tsx`** — KPI card with gradient accent bar, uppercase label, large value, optional subtitle.

**`SeverityBadge.tsx`** — Colored pill showing CRITICAL/WARNING/INFO.

**`StatusDot.tsx`** — 7px glowing circle for blocked/warning/allowed/clean status.

**`Panel.tsx`** — Surface-colored card container with border.

**`TimelineChart.tsx`** — Vertical bar chart showing hourly events with red block overlay. Uses inline styles for dynamic heights (Tailwind can't do data-driven heights).

**`ComplianceGauge.tsx`** — Horizontal progress bar with framework label and fraction text.

**`PageHeader.tsx`** — Page title + "Last updated" timestamp + LIVE indicator badge.

Each component should be a single exported function component with typed props. No state management — these are pure presentational components.

- [ ] **Step 2: Verify it compiles**

```bash
cd frontend && npm run build
```

Expected: Build succeeds.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/
git commit -m "feat: add shared UI components (StatCard, SeverityBadge, Panel, etc.)"
```

---

## Chunk 5: Frontend Dashboard Pages

### Task 19: Overview page

**Files:**
- Create: `frontend/src/pages/Overview.tsx`
- Create: `frontend/src/hooks/useApi.ts`

- [ ] **Step 1: Write `frontend/src/hooks/useApi.ts`**

A generic data-fetching hook that handles loading/error states and auto-refreshes.

```tsx
// frontend/src/hooks/useApi.ts
import { useState, useEffect, useCallback } from "react";

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await fetcher();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, deps);

  useEffect(() => { refetch(); }, [refetch]);

  return { data, loading, error, refetch };
}
```

- [ ] **Step 2: Write `frontend/src/pages/Overview.tsx`**

Fetches `/overview/stats` and `/overview/timeline`, renders 4 StatCards, TimelineChart, recent alerts (from `/alerts?per_page=4`), ComplianceGauges, and hook effectiveness (from `/hooks`). Uses `useApi` for all data fetching.

- [ ] **Step 3: Wire up in `App.tsx`**

Replace the Overview placeholder:

```tsx
import { Overview } from "./pages/Overview";
// ...
<Route index element={<Overview />} />
```

- [ ] **Step 4: Verify it compiles**

```bash
cd frontend && npm run build
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/Overview.tsx frontend/src/hooks/useApi.ts frontend/src/App.tsx
git commit -m "feat: add Overview dashboard page"
```

---

### Task 20: Live Alerts page with WebSocket

**Files:**
- Create: `frontend/src/pages/LiveAlerts.tsx`
- Create: `frontend/src/hooks/useWebSocket.ts`

- [ ] **Step 1: Write `frontend/src/hooks/useWebSocket.ts`**

```tsx
// frontend/src/hooks/useWebSocket.ts
import { useEffect, useRef, useCallback, useState } from "react";

export function useWebSocket(onMessage: (data: unknown) => void) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws`);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setTimeout(connect, 3000); // auto-reconnect
    };
    ws.onmessage = (event) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {}
    };

    wsRef.current = ws;
  }, [onMessage]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { connected };
}
```

- [ ] **Step 2: Write `frontend/src/pages/LiveAlerts.tsx`**

Combines REST-fetched alerts with WebSocket live updates. Shows severity filter buttons, expandable alert cards with detail grid (hook, event, developer, repository). New events from WebSocket are prepended to the list.

- [ ] **Step 3: Wire up in `App.tsx`**

Replace the Live Alerts placeholder.

- [ ] **Step 4: Verify it compiles**

```bash
cd frontend && npm run build
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/LiveAlerts.tsx frontend/src/hooks/useWebSocket.ts frontend/src/App.tsx
git commit -m "feat: add Live Alerts page with WebSocket real-time updates"
```

---

### Task 21: Hooks page

**Files:**
- Create: `frontend/src/pages/Hooks.tsx`

- [ ] **Step 1: Write `frontend/src/pages/Hooks.tsx`**

Fetches `/hooks`, renders a performance table with columns: Hook Name, Triggers, Blocks, Block Rate, Status. Sortable by clicking column headers. Uses `useApi`.

- [ ] **Step 2: Wire up in `App.tsx`**

- [ ] **Step 3: Verify and commit**

```bash
cd frontend && npm run build
git add frontend/src/pages/Hooks.tsx frontend/src/App.tsx
git commit -m "feat: add Hooks performance page"
```

---

### Task 22: Compliance page

**Files:**
- Create: `frontend/src/pages/Compliance.tsx`

- [ ] **Step 1: Write `frontend/src/pages/Compliance.tsx`**

Fetches `/compliance`, renders 4 StatCards (one per framework with percentage), followed by a control mapping table showing which hooks map to which framework controls. Uses ComplianceGauge components.

- [ ] **Step 2: Wire up in `App.tsx`**

- [ ] **Step 3: Verify and commit**

```bash
cd frontend && npm run build
git add frontend/src/pages/Compliance.tsx frontend/src/App.tsx
git commit -m "feat: add Compliance dashboard page"
```

---

### Task 23: Developers page

**Files:**
- Create: `frontend/src/pages/Developers.tsx`

- [ ] **Step 1: Write `frontend/src/pages/Developers.tsx`**

Fetches `/developers`, renders a risk profile table with columns: Developer, Session Activity (progress bar), Sessions, Blocks, Risk (badge). Uses `useApi`.

- [ ] **Step 2: Wire up in `App.tsx`**

- [ ] **Step 3: Verify and commit**

```bash
cd frontend && npm run build
git add frontend/src/pages/Developers.tsx frontend/src/App.tsx
git commit -m "feat: add Developers risk profile page"
```

---

### Task 24: Audit Log page

**Files:**
- Create: `frontend/src/pages/AuditLog.tsx`

- [ ] **Step 1: Write `frontend/src/pages/AuditLog.tsx`**

Fetches `/audit`, renders a paginated event table with columns: Timestamp, Developer, Hook, Event Detail, Result (colored badge). Includes pagination controls and Export CSV/Export JSON buttons that link to the export URLs from the API client.

- [ ] **Step 2: Wire up in `App.tsx`**

- [ ] **Step 3: Verify and commit**

```bash
cd frontend && npm run build
git add frontend/src/pages/AuditLog.tsx frontend/src/App.tsx
git commit -m "feat: add Audit Log page with export and pagination"
```

---

## Chunk 6: Integration & DevOps

### Task 25: Docker Compose and Makefile

**Files:**
- Create: `docker-compose.yml`
- Create: `Makefile`

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: tatu
      POSTGRES_USER: tatu
      POSTGRES_PASSWORD: tatu_dev
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

- [ ] **Step 2: Write `Makefile`**

```makefile
# Makefile
.PHONY: dev dev-backend dev-frontend test lint seed db

# Start both backend and frontend
dev: dev-backend dev-frontend

dev-backend:
	cd backend && source venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

test:
	cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/ -v

lint:
	cd backend && python -m ruff check app/ tests/
	cd frontend && npm run lint

seed:
	cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m app.seed

db:
	docker compose up -d db

migrate:
	cd backend && alembic upgrade head
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml Makefile
git commit -m "feat: add Docker Compose for PostgreSQL and Makefile for dev commands"
```

---

### Task 26: Update CLAUDE.md and add .gitignore entries

**Files:**
- Modify: `CLAUDE.md`
- Modify: `.gitignore`

- [ ] **Step 1: Update `.gitignore`**

```
.superpowers/
backend/venv/
backend/tatu.db
backend/__pycache__/
backend/**/__pycache__/
frontend/node_modules/
frontend/dist/
.env
*.pyc
```

- [ ] **Step 2: Update `CLAUDE.md`**

Update with actual build/test/dev commands now that the project is scaffolded. Include the monorepo structure, how to run backend and frontend, how to run tests, and how to seed data.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md .gitignore
git commit -m "docs: update CLAUDE.md with dev commands and project structure"
```

---

### Task 27: Run full test suite and verify end-to-end

- [ ] **Step 1: Run all backend tests**

```bash
cd backend && TATU_DASHBOARD_PASSWORD=testpass TATU_SECRET_KEY=testsecret python -m pytest tests/ -v
```

Expected: All tests PASS

- [ ] **Step 2: Build frontend**

```bash
cd frontend && npm run build
```

Expected: Build succeeds with no errors

- [ ] **Step 3: Manual smoke test**

Start both servers and verify:
1. Login page loads at http://localhost:5173
2. Login with password works
3. Overview page shows (with empty data)
4. All 6 nav items work
5. Health check returns OK at http://localhost:8000/api/v1/health

- [ ] **Step 4: Final commit if any adjustments needed**

```bash
git add -A && git commit -m "fix: address integration issues from smoke test"
```
