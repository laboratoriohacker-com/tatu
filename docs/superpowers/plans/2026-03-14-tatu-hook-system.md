# Tatu Hook System Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hybrid hook system with Nuclei-style YAML templates + YARA rules, a sync protocol for dynamic rule updates, a `tatu-hook` CLI for Claude Code integration, and a Rules dashboard page.

**Architecture:** Four independent subsystems: (1) Backend rule models + API with CRUD and sync endpoints, (2) Built-in rule library of ~40 YAML/YARA templates loaded on startup, (3) `tatu-hook` CLI package that runs locally as a Claude Code hook with local-first blocking + async event reporting, (4) Frontend Rules page with table, editor, and audit badge support.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0, Pydantic v2, PyYAML, yara-python (optional), React 18, TypeScript, Tailwind CSS.

**Spec:** `docs/superpowers/specs/2026-03-14-tatu-hook-system-design.md`

---

## Chunk 1: Backend Rule Models & API

### Task 1: Rule and RuleVersion models

**Files:**
- Create: `backend/app/models/rule.py`
- Create: `backend/app/models/rule_version.py`
- Modify: `backend/app/main.py` (register models)

- [ ] **Step 1: Write test for Rule model**

```python
# backend/tests/test_models_rule.py
import uuid
import pytest
from sqlalchemy import select

from tests.conftest import async_session_fixture


@pytest.fixture
async def db():
    async for session in async_session_fixture():
        yield session


@pytest.mark.asyncio
async def test_create_rule(db):
    from app.models.rule import Rule

    rule = Rule(
        id="test-aws-key",
        name="Test AWS Key",
        format="yaml",
        content="id: test-aws-key\ninfo:\n  name: Test",
        source="custom",
        enabled=True,
        category="secrets",
        severity="critical",
        mode="audit",
        action="block",
        hook_event="PreToolUse",
        matcher="Write|Edit",
        version_added=1,
    )
    db.add(rule)
    await db.commit()

    result = await db.execute(select(Rule).where(Rule.id == "test-aws-key"))
    fetched = result.scalar_one()
    assert fetched.name == "Test AWS Key"
    assert fetched.mode == "audit"
    assert fetched.source == "custom"


@pytest.mark.asyncio
async def test_create_rule_version(db):
    from app.models.rule_version import RuleVersion

    rv = RuleVersion(id=1, version=1)
    db.add(rv)
    await db.commit()

    result = await db.execute(select(RuleVersion).where(RuleVersion.id == 1))
    fetched = result.scalar_one()
    assert fetched.version == 1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker compose --profile test run --rm test tests/test_models_rule.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'app.models.rule'`

- [ ] **Step 3: Write Rule model**

```python
# backend/app/models/rule.py
from sqlalchemy import String, Text, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    format: Mapped[str] = mapped_column(String(10))  # yaml | yara
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(10))  # builtin | custom
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(10), default="audit")  # audit | strict
    action: Mapped[str] = mapped_column(String(10))  # block | warn | log
    hook_event: Mapped[str] = mapped_column(String(50))
    matcher: Mapped[str] = mapped_column(String(255))
    version_added: Mapped[int] = mapped_column(Integer, default=1)
```

- [ ] **Step 4: Write RuleVersion model**

```python
# backend/app/models/rule_version.py
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class RuleVersion(Base):
    __tablename__ = "rule_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
```

- [ ] **Step 5: Register models in main.py**

Add imports to `backend/app/main.py` alongside the existing model imports:

```python
import app.models.rule  # noqa: F401
import app.models.rule_version  # noqa: F401
```

- [ ] **Step 6: Run test to verify it passes**

```bash
docker compose --profile test run --rm test tests/test_models_rule.py -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/models/rule.py backend/app/models/rule_version.py backend/app/main.py backend/tests/test_models_rule.py
git commit -m "feat: add Rule and RuleVersion models"
```

---

### Task 2: Rule schemas

**Files:**
- Create: `backend/app/schemas/rule.py`

- [ ] **Step 1: Write test for rule schemas**

```python
# backend/tests/test_schemas_rule.py
import pytest
from pydantic import ValidationError


def test_rule_create_valid():
    from app.schemas.rule import RuleCreate

    rule = RuleCreate(
        id="test-rule",
        name="Test Rule",
        format="yaml",
        content="id: test-rule\ninfo:\n  name: Test",
        category="secrets",
        severity="critical",
        mode="audit",
        action="block",
        hook_event="PreToolUse",
        matcher="Write|Edit",
    )
    assert rule.id == "test-rule"
    assert rule.mode == "audit"


def test_rule_create_default_mode():
    from app.schemas.rule import RuleCreate

    rule = RuleCreate(
        id="test-rule",
        name="Test Rule",
        format="yaml",
        content="content",
        category="secrets",
        severity="critical",
        action="block",
        hook_event="PreToolUse",
        matcher="Write",
    )
    assert rule.mode == "audit"


def test_rule_create_invalid_format():
    from app.schemas.rule import RuleCreate

    with pytest.raises(ValidationError):
        RuleCreate(
            id="x", name="x", format="invalid", content="x",
            category="x", severity="x", action="x",
            hook_event="PreToolUse", matcher="x",
        )


def test_rule_create_invalid_mode():
    from app.schemas.rule import RuleCreate

    with pytest.raises(ValidationError):
        RuleCreate(
            id="x", name="x", format="yaml", content="x",
            category="x", severity="x", mode="invalid", action="x",
            hook_event="PreToolUse", matcher="x",
        )


def test_rule_sync_response():
    from app.schemas.rule import RuleSyncResponse, RuleSyncItem

    resp = RuleSyncResponse(
        version=5,
        updated_at="2026-03-14T12:00:00Z",
        rules=[RuleSyncItem(id="r1", format="yaml", content="content")],
    )
    assert resp.version == 5
    assert len(resp.rules) == 1


def test_rule_sync_up_to_date():
    from app.schemas.rule import RuleSyncUpToDate

    resp = RuleSyncUpToDate(version=5, status="up_to_date")
    assert resp.status == "up_to_date"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker compose --profile test run --rm test tests/test_schemas_rule.py -v
```

- [ ] **Step 3: Write rule schemas**

```python
# backend/app/schemas/rule.py
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class RuleCreate(BaseModel):
    id: str
    name: str
    format: Literal["yaml", "yara"]
    content: str
    category: str
    severity: Literal["critical", "warning", "info"]
    mode: Literal["audit", "strict"] = "audit"
    action: Literal["block", "warn", "log"]
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ]
    matcher: str


class RuleUpdate(BaseModel):
    name: str | None = None
    content: str | None = None
    category: str | None = None
    severity: Literal["critical", "warning", "info"] | None = None
    mode: Literal["audit", "strict"] | None = None
    action: Literal["block", "warn", "log"] | None = None
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ] | None = None
    matcher: str | None = None
    enabled: bool | None = None


class RuleResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    format: str
    content: str
    source: str
    enabled: bool
    category: str
    severity: str
    mode: str
    action: str
    hook_event: str
    matcher: str
    version_added: int


class RuleSyncItem(BaseModel):
    id: str
    format: str
    content: str


class RuleSyncResponse(BaseModel):
    version: int
    updated_at: str
    rules: list[RuleSyncItem]


class RuleSyncUpToDate(BaseModel):
    version: int
    status: str = "up_to_date"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
docker compose --profile test run --rm test tests/test_schemas_rule.py -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas/rule.py backend/tests/test_schemas_rule.py
git commit -m "feat: add Rule schemas with validation"
```

---

### Task 3: Rule service (version bumping + CRUD logic)

**Files:**
- Create: `backend/app/services/rule_service.py`

- [ ] **Step 1: Write test for rule service**

```python
# backend/tests/test_rule_service.py
import pytest
from sqlalchemy import select

from tests.conftest import async_session_fixture


@pytest.fixture
async def db():
    async for session in async_session_fixture():
        yield session


@pytest.mark.asyncio
async def test_get_current_version_initializes(db):
    from app.services.rule_service import get_current_version

    version = await get_current_version(db)
    assert version >= 1


@pytest.mark.asyncio
async def test_bump_version(db):
    from app.services.rule_service import get_current_version, bump_version

    v1 = await get_current_version(db)
    v2 = await bump_version(db)
    assert v2 == v1 + 1


@pytest.mark.asyncio
async def test_create_custom_rule(db):
    from app.services.rule_service import create_rule, bump_version
    from app.schemas.rule import RuleCreate

    await bump_version(db)

    body = RuleCreate(
        id="custom-test",
        name="Custom Test",
        format="yaml",
        content="test content",
        category="secrets",
        severity="critical",
        mode="strict",
        action="block",
        hook_event="PreToolUse",
        matcher="Write",
    )
    rule = await create_rule(db, body)
    assert rule.id == "custom-test"
    assert rule.source == "custom"
    assert rule.mode == "strict"


@pytest.mark.asyncio
async def test_list_rules(db):
    from app.services.rule_service import create_rule, list_rules
    from app.schemas.rule import RuleCreate

    body = RuleCreate(
        id="list-test",
        name="List Test",
        format="yaml",
        content="content",
        category="pii",
        severity="warning",
        action="warn",
        hook_event="PreToolUse",
        matcher="Write",
    )
    await create_rule(db, body)
    rules = await list_rules(db)
    assert any(r.id == "list-test" for r in rules)


@pytest.mark.asyncio
async def test_get_enabled_rules_for_sync(db):
    from app.services.rule_service import create_rule, get_enabled_rules
    from app.schemas.rule import RuleCreate

    body = RuleCreate(
        id="sync-test",
        name="Sync Test",
        format="yaml",
        content="sync content",
        category="secrets",
        severity="critical",
        action="block",
        hook_event="PreToolUse",
        matcher="Bash",
    )
    await create_rule(db, body)
    rules = await get_enabled_rules(db)
    assert any(r.id == "sync-test" for r in rules)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker compose --profile test run --rm test tests/test_rule_service.py -v
```

- [ ] **Step 3: Write rule service**

```python
# backend/app/services/rule_service.py
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule import Rule
from app.models.rule_version import RuleVersion
from app.schemas.rule import RuleCreate, RuleUpdate


async def get_current_version(db: AsyncSession) -> int:
    result = await db.execute(select(RuleVersion).where(RuleVersion.id == 1))
    rv = result.scalar_one_or_none()
    if not rv:
        rv = RuleVersion(id=1, version=1)
        db.add(rv)
        await db.commit()
    return rv.version


async def bump_version(db: AsyncSession) -> int:
    result = await db.execute(select(RuleVersion).where(RuleVersion.id == 1))
    rv = result.scalar_one_or_none()
    if not rv:
        rv = RuleVersion(id=1, version=1)
        db.add(rv)
        await db.flush()
    rv.version += 1
    await db.commit()
    return rv.version


async def create_rule(db: AsyncSession, body: RuleCreate) -> Rule:
    version = await get_current_version(db)
    rule = Rule(
        id=body.id,
        name=body.name,
        format=body.format,
        content=body.content,
        source="custom",
        enabled=True,
        category=body.category,
        severity=body.severity,
        mode=body.mode,
        action=body.action,
        hook_event=body.hook_event,
        matcher=body.matcher,
        version_added=version,
    )
    db.add(rule)
    await bump_version(db)
    return rule


async def update_rule(db: AsyncSession, rule_id: str, body: RuleUpdate) -> Rule | None:
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return None
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    rule.version_added = await bump_version(db)
    return rule


async def disable_rule(db: AsyncSession, rule_id: str) -> Rule | None:
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return None
    rule.enabled = False
    await bump_version(db)
    return rule


async def list_rules(
    db: AsyncSession,
    category: str | None = None,
    source: str | None = None,
) -> list[Rule]:
    query = select(Rule)
    if category:
        query = query.where(Rule.category == category)
    if source:
        query = query.where(Rule.source == source)
    result = await db.execute(query.order_by(Rule.category, Rule.name))
    return list(result.scalars().all())


async def get_enabled_rules(db: AsyncSession) -> list[Rule]:
    result = await db.execute(
        select(Rule).where(Rule.enabled == True).order_by(Rule.category, Rule.id)
    )
    return list(result.scalars().all())


async def upsert_builtin_rule(db: AsyncSession, rule_data: dict) -> None:
    result = await db.execute(select(Rule).where(Rule.id == rule_data["id"]))
    existing = result.scalar_one_or_none()
    if existing and existing.source == "builtin":
        for field, value in rule_data.items():
            if field != "id":
                setattr(existing, field, value)
    elif not existing:
        db.add(Rule(**rule_data, source="builtin"))
```

- [ ] **Step 4: Run test to verify it passes**

```bash
docker compose --profile test run --rm test tests/test_rule_service.py -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/rule_service.py backend/tests/test_rule_service.py
git commit -m "feat: add rule service with CRUD and version bumping"
```

---

### Task 4: Rules router (CRUD + sync endpoint)

**Files:**
- Create: `backend/app/routers/rules.py`
- Modify: `backend/app/main.py` (register router)

- [ ] **Step 1: Write test for rules router**

```python
# backend/tests/test_router_rules.py
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import engine
from app.models import Base


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Login to get session cookie
        resp = await c.post("/api/v1/auth/login", json={"password": "testpass"})
        assert resp.status_code == 200
        yield c
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_create_rule(client):
    resp = await client.post("/api/v1/rules", json={
        "id": "test-create",
        "name": "Test Create",
        "format": "yaml",
        "content": "id: test-create",
        "category": "secrets",
        "severity": "critical",
        "mode": "audit",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "Write",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["id"] == "test-create"
    assert data["source"] == "custom"
    assert data["mode"] == "audit"


@pytest.mark.asyncio
async def test_list_rules(client):
    await client.post("/api/v1/rules", json={
        "id": "test-list",
        "name": "Test List",
        "format": "yaml",
        "content": "content",
        "category": "pii",
        "severity": "warning",
        "action": "warn",
        "hook_event": "PreToolUse",
        "matcher": "Write",
    })
    resp = await client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert any(r["id"] == "test-list" for r in rules)


@pytest.mark.asyncio
async def test_update_rule(client):
    await client.post("/api/v1/rules", json={
        "id": "test-update",
        "name": "Before",
        "format": "yaml",
        "content": "content",
        "category": "secrets",
        "severity": "critical",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "Write",
    })
    resp = await client.put("/api/v1/rules/test-update", json={
        "name": "After",
        "mode": "strict",
    })
    assert resp.status_code == 200
    assert resp.json()["name"] == "After"
    assert resp.json()["mode"] == "strict"


@pytest.mark.asyncio
async def test_delete_rule(client):
    await client.post("/api/v1/rules", json={
        "id": "test-delete",
        "name": "Delete Me",
        "format": "yaml",
        "content": "content",
        "category": "secrets",
        "severity": "critical",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "Write",
    })
    resp = await client.delete("/api/v1/rules/test-delete")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_sync_no_rules(client):
    resp = await client.get("/api/v1/rules/sync?version=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "version" in data


@pytest.mark.asyncio
async def test_sync_up_to_date(client):
    # Create a rule so version bumps
    await client.post("/api/v1/rules", json={
        "id": "sync-test",
        "name": "Sync",
        "format": "yaml",
        "content": "content",
        "category": "secrets",
        "severity": "critical",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "Write",
    })
    # Get current version
    resp1 = await client.get("/api/v1/rules/sync?version=0")
    current_version = resp1.json()["version"]

    # Sync with current version should be up_to_date
    resp2 = await client.get(f"/api/v1/rules/sync?version={current_version}")
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "up_to_date"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker compose --profile test run --rm test tests/test_router_rules.py -v
```

- [ ] **Step 3: Write rules router**

```python
# backend/app/routers/rules.py
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth, require_api_key
from app.database import get_db
from app.schemas.rule import (
    RuleCreate, RuleUpdate, RuleResponse,
    RuleSyncResponse, RuleSyncUpToDate, RuleSyncItem,
)
from app.services.rule_service import (
    create_rule, update_rule, disable_rule,
    list_rules, get_enabled_rules, get_current_version,
)

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("", response_model=list[RuleResponse],
            dependencies=[Depends(require_dashboard_auth)])
async def list_rules_endpoint(
    category: str | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    return await list_rules(db, category=category, source=source)


@router.post("", response_model=RuleResponse, status_code=201,
             dependencies=[Depends(require_dashboard_auth)])
async def create_rule_endpoint(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
):
    return await create_rule(db, body)


@router.put("/{rule_id}", response_model=RuleResponse,
            dependencies=[Depends(require_dashboard_auth)])
async def update_rule_endpoint(
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    rule = await update_rule(db, rule_id, body)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.delete("/{rule_id}", status_code=204,
               dependencies=[Depends(require_dashboard_auth)])
async def delete_rule_endpoint(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    rule = await disable_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.get("/sync")
async def sync_rules(
    version: int = 0,
    db: AsyncSession = Depends(get_db),
):
    current = await get_current_version(db)
    if version >= current:
        return RuleSyncUpToDate(version=current)

    rules = await get_enabled_rules(db)
    return RuleSyncResponse(
        version=current,
        updated_at=datetime.now(timezone.utc).isoformat(),
        rules=[
            RuleSyncItem(id=r.id, format=r.format, content=r.content)
            for r in rules
        ],
    )
```

- [ ] **Step 4: Register router in main.py**

Add to `backend/app/main.py`:

```python
from app.routers import rules as rules_router
# ...
app.include_router(rules_router.router)
```

- [ ] **Step 5: Run test to verify it passes**

```bash
docker compose --profile test run --rm test tests/test_router_rules.py -v
```

- [ ] **Step 6: Run full test suite**

```bash
docker compose --profile test run --rm test -v
```

Expected: All tests PASS (existing + new)

- [ ] **Step 7: Commit**

```bash
git add backend/app/routers/rules.py backend/app/main.py backend/tests/test_router_rules.py
git commit -m "feat: add rules CRUD router with sync endpoint"
```

---

### Task 5: Update Event schema for audit_block status

**Files:**
- Modify: `backend/app/schemas/event.py`
- Modify: `frontend/src/lib/types.ts`

- [ ] **Step 1: Update EventCreate status to include audit_block**

In `backend/app/schemas/event.py`, update the `status` field:

```python
status: Literal["blocked", "warning", "allowed", "clean", "audit_block"]
```

- [ ] **Step 2: Run existing tests to ensure nothing breaks**

```bash
docker compose --profile test run --rm test -v
```

- [ ] **Step 3: Update frontend types**

In `frontend/src/lib/types.ts`, update the Event status type:

```typescript
status: "blocked" | "warning" | "allowed" | "clean" | "audit_block";
```

- [ ] **Step 4: Build frontend to verify**

```bash
docker compose --profile build run --rm frontend-build
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas/event.py frontend/src/lib/types.ts
git commit -m "feat: add audit_block status for audit mode events"
```

---

## Chunk 2: Built-in Rule Library

### Task 6: YAML rule loader service

**Files:**
- Create: `backend/app/services/rule_loader.py`

- [ ] **Step 1: Add PyYAML to requirements.txt**

Add to `backend/requirements.txt`:

```
pyyaml==6.*
```

- [ ] **Step 2: Write test for YAML rule loader**

```python
# backend/tests/test_rule_loader.py
import pytest
import tempfile
import os


def test_parse_yaml_rule():
    from app.services.rule_loader import parse_yaml_rule

    content = """id: test-rule
info:
  name: Test Rule
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - test

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - 'test_pattern'

message: "Test message"
"""
    rule = parse_yaml_rule(content, "test.yaml")
    assert rule["id"] == "test-rule"
    assert rule["name"] == "Test Rule"
    assert rule["severity"] == "critical"
    assert rule["category"] == "secrets"
    assert rule["mode"] == "audit"
    assert rule["action"] == "block"
    assert rule["hook_event"] == "PreToolUse"
    assert rule["matcher"] == "Write|Edit"
    assert rule["format"] == "yaml"


def test_parse_yaml_rule_default_mode():
    from app.services.rule_loader import parse_yaml_rule

    content = """id: no-mode
info:
  name: No Mode Rule
  severity: warning
  category: sast

hook:
  event: PostToolUse
  matcher: Bash
  action: warn

detect:
  type: regex
  patterns:
    - 'pattern'

message: "msg"
"""
    rule = parse_yaml_rule(content, "no-mode.yaml")
    assert rule["mode"] == "audit"


def test_load_rules_from_directory():
    from app.services.rule_loader import load_rules_from_directory

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a YAML rule
        os.makedirs(os.path.join(tmpdir, "secrets"))
        with open(os.path.join(tmpdir, "secrets", "test.yaml"), "w") as f:
            f.write("""id: dir-test
info:
  name: Dir Test
  severity: critical
  category: secrets

hook:
  event: PreToolUse
  matcher: Write
  action: block

detect:
  type: regex
  patterns:
    - 'secret'

message: "found"
""")
        rules = load_rules_from_directory(tmpdir)
        assert len(rules) == 1
        assert rules[0]["id"] == "dir-test"


def test_parse_yara_metadata():
    from app.services.rule_loader import parse_yara_rule

    content = """rule test_yara {
  meta:
    id = "yara-test"
    severity = "critical"
    category = "secrets"
    action = "block"
    mode = "strict"
    hook_event = "PreToolUse"
    matcher = "Write|Edit"
  strings:
    $a = "test" ascii
  condition:
    $a
}"""
    rule = parse_yara_rule(content, "test.yar")
    assert rule["id"] == "yara-test"
    assert rule["mode"] == "strict"
    assert rule["format"] == "yara"
```

- [ ] **Step 3: Run test to verify it fails**

```bash
docker compose --profile test run --rm test tests/test_rule_loader.py -v
```

- [ ] **Step 4: Write rule loader service**

```python
# backend/app/services/rule_loader.py
import os
import re
from pathlib import Path

import yaml


def parse_yaml_rule(content: str, filename: str) -> dict:
    data = yaml.safe_load(content)
    info = data.get("info", {})
    hook = data.get("hook", {})
    return {
        "id": data["id"],
        "name": info.get("name", data["id"]),
        "format": "yaml",
        "content": content,
        "enabled": True,
        "category": info.get("category", "uncategorized"),
        "severity": info.get("severity", "info"),
        "mode": hook.get("mode", "audit"),
        "action": hook.get("action", "log"),
        "hook_event": hook.get("event", "PreToolUse"),
        "matcher": hook.get("matcher", ".*"),
        "version_added": 1,
    }


def parse_yara_rule(content: str, filename: str) -> dict:
    meta = {}
    meta_match = re.search(r"meta:\s*\n((?:\s+\w+\s*=\s*\"[^\"]*\"\s*\n)+)", content)
    if meta_match:
        for line in meta_match.group(1).strip().split("\n"):
            m = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"', line)
            if m:
                meta[m.group(1)] = m.group(2)

    return {
        "id": meta.get("id", Path(filename).stem),
        "name": meta.get("id", Path(filename).stem).replace("-", " ").title(),
        "format": "yara",
        "content": content,
        "enabled": True,
        "category": meta.get("category", "uncategorized"),
        "severity": meta.get("severity", "info"),
        "mode": meta.get("mode", "audit"),
        "action": meta.get("action", "log"),
        "hook_event": meta.get("hook_event", "PreToolUse"),
        "matcher": meta.get("matcher", ".*"),
        "version_added": 1,
    }


def load_rules_from_directory(rules_dir: str) -> list[dict]:
    rules = []
    for root, _dirs, files in os.walk(rules_dir):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            with open(filepath) as f:
                content = f.read()
            if filename.endswith((".yaml", ".yml")):
                rules.append(parse_yaml_rule(content, filename))
            elif filename.endswith((".yar", ".yara")):
                rules.append(parse_yara_rule(content, filename))
    return rules
```

- [ ] **Step 5: Run test to verify it passes**

```bash
docker compose --profile test run --rm test tests/test_rule_loader.py -v
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/rule_loader.py backend/tests/test_rule_loader.py backend/requirements.txt
git commit -m "feat: add YAML and YARA rule loader service"
```

---

### Task 7: Built-in rule templates (secrets + pii)

**Files:**
- Create: `rules/secrets/*.yaml` (10 files)
- Create: `rules/pii/*.yaml` (3 files)

- [ ] **Step 1: Create secrets rules**

Create each file in `rules/secrets/`:

`rules/secrets/aws-access-key.yaml`:
```yaml
id: aws-access-key
info:
  name: AWS Access Key ID
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - aws
    - cloud

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[A-Z0-9]{16}\b'
    - '(?i)aws_secret_access_key\s*[:=]\s*[''"]?[A-Za-z0-9/+=]{40}'

message: "AWS access key detected — submission blocked"
```

`rules/secrets/github-token.yaml`:
```yaml
id: github-token
info:
  name: GitHub Token
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - github
    - scm

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b'
    - '\bgithub_pat_[A-Za-z0-9_]{20,255}\b'

message: "GitHub token detected — submission blocked"
```

`rules/secrets/private-key.yaml`:
```yaml
id: private-key
info:
  name: Private Key (PEM)
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - crypto
    - key

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----'
    - '-----BEGIN OPENSSH PRIVATE KEY-----'
    - '-----BEGIN PGP PRIVATE KEY BLOCK-----'

message: "Private key detected — submission blocked"
```

`rules/secrets/stripe-key.yaml`:
```yaml
id: stripe-key
info:
  name: Stripe Secret Key
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - stripe
    - payments

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\b(?:r|s)k_(?:live|test)_[0-9A-Za-z]{24,}\b'

message: "Stripe secret key detected — submission blocked"
```

`rules/secrets/generic-api-key.yaml`:
```yaml
id: generic-api-key
info:
  name: Generic API Key Assignment
  author: tatu-core
  severity: warning
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - generic

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '(?i)(?:api_?key|api_?secret|access_?token)\s*[:=]\s*[''"][A-Za-z0-9_\-]{20,}[''"]'

message: "Possible API key assignment detected — review before committing"
```

`rules/secrets/password-assignment.yaml`:
```yaml
id: password-assignment
info:
  name: Hardcoded Password
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - password

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[''"][^''"]{8,}[''"]'

message: "Hardcoded password detected — use environment variables or a secrets manager"
```

`rules/secrets/slack-token.yaml`:
```yaml
id: slack-token
info:
  name: Slack Token
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - slack

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - 'xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+'
    - 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'

message: "Slack token or webhook URL detected — submission blocked"
```

`rules/secrets/google-api-key.yaml`:
```yaml
id: google-api-key
info:
  name: Google API Key
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - google
    - cloud

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\bAIza[0-9A-Za-z\-_]{35}\b'

message: "Google API key detected — submission blocked"
```

`rules/secrets/anthropic-key.yaml`:
```yaml
id: anthropic-key
info:
  name: Anthropic API Key
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
  tags:
    - anthropic
    - ai

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\bsk-ant-api\d+-[A-Za-z0-9_-]{90,}\b'

message: "Anthropic API key detected — submission blocked"
```

`rules/secrets/basic-auth-url.yaml`:
```yaml
id: basic-auth-url
info:
  name: Basic Auth Credentials in URL
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - auth
    - url

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '://[^:/?#\[\]@!$&''()*+,;=\s]+:[^:/?#\[\]@!$&''()*+,;=\s]+@'

message: "Credentials embedded in URL detected — use environment variables"
```

- [ ] **Step 2: Create PII rules**

`rules/pii/brazilian-cpf.yaml`:
```yaml
id: brazilian-cpf
info:
  name: Brazilian CPF Number
  author: tatu-core
  severity: critical
  category: pii
  compliance:
    - LGPD Art. 37
    - LGPD Art. 46
  tags:
    - lgpd
    - brazil
    - pii

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'

message: "Brazilian CPF number detected — PII must not be hardcoded (LGPD Art. 46)"
```

`rules/pii/brazilian-cnpj.yaml`:
```yaml
id: brazilian-cnpj
info:
  name: Brazilian CNPJ Number
  author: tatu-core
  severity: critical
  category: pii
  compliance:
    - LGPD Art. 37
    - LGPD Art. 46
  tags:
    - lgpd
    - brazil
    - pii

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b'

message: "Brazilian CNPJ number detected — PII must not be hardcoded (LGPD Art. 46)"
```

`rules/pii/email-address.yaml`:
```yaml
id: email-in-code
info:
  name: Email Address in Code
  author: tatu-core
  severity: warning
  category: pii
  compliance:
    - LGPD Art. 46
  tags:
    - pii
    - email

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

message: "Email address found in code — consider using placeholders or env variables"
```

- [ ] **Step 3: Verify rules load correctly**

```python
# Quick validation
docker compose run --rm backend python -c "
from app.services.rule_loader import load_rules_from_directory
rules = load_rules_from_directory('/app/../rules')
print(f'Loaded {len(rules)} rules')
for r in rules:
    print(f'  {r[\"id\"]} ({r[\"category\"]}) mode={r[\"mode\"]}')
"
```

- [ ] **Step 4: Commit**

```bash
git add rules/
git commit -m "feat: add built-in rule templates for secrets and PII detection"
```

---

### Task 8: Built-in rule templates (destructive + sast + files)

**Files:**
- Create: `rules/destructive/*.yaml` (3 files)
- Create: `rules/sast/*.yaml` (3 files)
- Create: `rules/files/*.yaml` (2 files)
- Create: `rules/yara/*.yar` (1 file)

- [ ] **Step 1: Create destructive command rules**

`rules/destructive/rm-rf.yaml`:
```yaml
id: destructive-rm-rf
info:
  name: Destructive rm Command
  author: tatu-core
  severity: critical
  category: destructive
  compliance:
    - CPS234 Op. Risk
    - ISO 27001 A.12.4
  tags:
    - bash
    - filesystem

hook:
  event: PreToolUse
  matcher: Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|.*--force\s+).*/'
    - '\brm\s+-[a-zA-Z]*r[a-zA-Z]*f'
    - '\bmkfs\b'
    - '\bdd\s+if='

message: "Destructive filesystem command detected — operation blocked"
```

`rules/destructive/sql-drop.yaml`:
```yaml
id: destructive-sql-drop
info:
  name: SQL DROP Statement
  author: tatu-core
  severity: critical
  category: destructive
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.12.4
  tags:
    - sql
    - database

hook:
  event: PreToolUse
  matcher: Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b'
    - '(?i)\bTRUNCATE\s+TABLE\b'

message: "Destructive SQL statement detected — operation blocked"
```

`rules/destructive/git-force-push.yaml`:
```yaml
id: destructive-git-force-push
info:
  name: Git Force Push to Protected Branch
  author: tatu-core
  severity: critical
  category: destructive
  compliance:
    - SOC2 CC8.1
    - ISO 27001 A.12.1.2
  tags:
    - git
    - scm

hook:
  event: PreToolUse
  matcher: Bash
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\bgit\s+push\s+.*--force'
    - '\bgit\s+push\s+-f\b'
    - '\bgit\s+reset\s+--hard\b'

message: "Destructive git operation detected — use --force-with-lease or avoid force push"
```

- [ ] **Step 2: Create SAST rules**

`rules/sast/sql-injection.yaml`:
```yaml
id: sast-sqli-string-concat
info:
  name: SQL Injection — String Interpolation
  author: tatu-core
  severity: critical
  category: sast
  compliance:
    - SOC2 CC8.1
    - ISO 27001 A.14.2
  tags:
    - sqli
    - cwe-89

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - 'f["\'']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s.+\{.*\}'
    - '(?:SELECT|INSERT|UPDATE|DELETE)\s.+\.format\s*\('
    - '(?:SELECT|INSERT|UPDATE|DELETE)\s.*["'']\s*\+\s*\w+'

message: "SQL injection risk: query uses string interpolation (CWE-89). Use parameterized queries."
```

`rules/sast/xss.yaml`:
```yaml
id: sast-xss
info:
  name: XSS — Unsafe DOM Manipulation
  author: tatu-core
  severity: warning
  category: sast
  compliance:
    - SOC2 CC8.1
  tags:
    - xss
    - cwe-79

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '\.innerHTML\s*='
    - 'document\.write\s*\('
    - 'dangerouslySetInnerHTML'
    - '\bv-html\b'

message: "Potential XSS: unsafe DOM manipulation detected (CWE-79). Use safe alternatives."
```

`rules/sast/command-injection.yaml`:
```yaml
id: sast-command-injection
info:
  name: Command Injection — Unsafe Shell Execution
  author: tatu-core
  severity: critical
  category: sast
  compliance:
    - SOC2 CC8.1
    - ISO 27001 A.14.2
  tags:
    - command-injection
    - cwe-78

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '\bos\.system\s*\('
    - '\bos\.popen\s*\('
    - 'subprocess\.\w+\(.*shell\s*=\s*True'
    - '\beval\s*\(\s*input'
    - '\bexec\s*\(\s*input'

message: "Command injection risk: unsafe shell execution detected (CWE-78). Use subprocess with shell=False."
```

- [ ] **Step 3: Create file protection rules**

`rules/files/protected-paths.yaml`:
```yaml
id: protected-paths
info:
  name: Protected File Modification
  author: tatu-core
  severity: critical
  category: files
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  tags:
    - filesystem
    - protection

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - '(?:^|/)\.env(?:\.|$)'
    - '(?:^|/)\.github/workflows/'
    - '/etc/shadow'
    - '/etc/passwd'
    - '(?:^|/)id_rsa'
    - '(?:^|/)id_ed25519'

message: "Modification of protected file detected — review required"
```

`rules/files/lockfile-modification.yaml`:
```yaml
id: lockfile-modification
info:
  name: Lockfile Modification Warning
  author: tatu-core
  severity: warning
  category: files
  compliance:
    - SOC2 CC7.1
  tags:
    - dependencies
    - supply-chain

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '(?:^|/)package-lock\.json$'
    - '(?:^|/)yarn\.lock$'
    - '(?:^|/)poetry\.lock$'
    - '(?:^|/)Pipfile\.lock$'

message: "Lockfile modification detected — verify dependency changes are intentional"
```

- [ ] **Step 4: Create YARA rule**

`rules/yara/private-key-multi.yar`:
```yara
rule private_key_pem {
  meta:
    id = "yara-private-key"
    severity = "critical"
    category = "secrets"
    action = "block"
    mode = "audit"
    hook_event = "PreToolUse"
    matcher = "Write|Edit|Read"
  strings:
    $begin = "-----BEGIN" ascii
    $private = "PRIVATE KEY-----" ascii
    $end = "-----END" ascii
  condition:
    $begin and $private and $end
}
```

- [ ] **Step 5: Verify all rules load**

```bash
docker compose run --rm backend python -c "
from app.services.rule_loader import load_rules_from_directory
rules = load_rules_from_directory('/app/../rules')
print(f'Loaded {len(rules)} rules')
cats = {}
for r in rules:
    cats[r['category']] = cats.get(r['category'], 0) + 1
for cat, count in sorted(cats.items()):
    print(f'  {cat}: {count}')
"
```

Expected: ~22 rules across secrets, pii, destructive, sast, files, uncategorized (yara)

- [ ] **Step 6: Commit**

```bash
git add rules/
git commit -m "feat: add built-in rule templates (destructive, SAST, files, YARA)"
```

---

### Task 9: Load built-in rules on startup

**Files:**
- Modify: `backend/app/main.py`

- [ ] **Step 1: Write test for startup rule loading**

```python
# backend/tests/test_rule_loader_startup.py
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport


@pytest_asyncio.fixture
async def client():
    from app.main import app
    from app.database import engine
    from app.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/auth/login", json={"password": "testpass"})
        assert resp.status_code == 200
        yield c
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_builtin_rules_loaded(client):
    resp = await client.get("/api/v1/rules?source=builtin")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) > 0
    assert any(r["id"] == "aws-access-key" for r in rules)
    assert all(r["source"] == "builtin" for r in rules)
```

- [ ] **Step 2: Update main.py lifespan to load built-in rules**

In `backend/app/main.py`, update the lifespan function:

```python
import os
from app.services.rule_loader import load_rules_from_directory
from app.services.rule_service import upsert_builtin_rule

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Load built-in rules from rules/ directory
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
    if os.path.isdir(rules_dir):
        rule_defs = load_rules_from_directory(rules_dir)
        async with async_session() as db:
            for rule_data in rule_defs:
                await upsert_builtin_rule(db, rule_data)
            await db.commit()

    yield
    await engine.dispose()
```

Also add the `async_session` import:

```python
from app.database import engine, async_session
```

- [ ] **Step 3: Run tests**

```bash
docker compose --profile test run --rm test tests/test_rule_loader_startup.py -v
```

- [ ] **Step 4: Run full test suite**

```bash
docker compose --profile test run --rm test -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/main.py backend/tests/test_rule_loader_startup.py
git commit -m "feat: load built-in rules from rules/ directory on startup"
```

---

## Chunk 3: tatu-hook CLI

### Task 10: CLI project scaffolding

**Files:**
- Create: `tatu-hook/pyproject.toml`
- Create: `tatu-hook/src/tatu_hook/__init__.py`
- Create: `tatu-hook/src/tatu_hook/cli.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
# tatu-hook/pyproject.toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "tatu-hook"
version = "0.1.0"
description = "Claude Code security hook for the Tatu DevSecOps platform"
requires-python = ">=3.10"
dependencies = [
    "pyyaml>=6.0",
]

[project.optional-dependencies]
yara = ["yara-python>=4.5"]
dev = ["pytest>=8.0"]

[project.scripts]
tatu-hook = "tatu_hook.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

- [ ] **Step 2: Create __init__.py**

```python
# tatu-hook/src/tatu_hook/__init__.py
__version__ = "0.1.0"
```

- [ ] **Step 3: Create minimal CLI entrypoint**

```python
# tatu-hook/src/tatu_hook/cli.py
"""Tatu Hook — Claude Code security hook CLI."""
from __future__ import annotations

import argparse
import sys

from tatu_hook import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"Tatu Hook v{__version__} — Claude Code security hook"
    )
    p.add_argument("--version", action="version", version=f"tatu-hook {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("init", help="Initialize tatu-hook configuration")
    event_parser = sub.add_parser("run", help="Run hook event handler")
    event_parser.add_argument(
        "--event",
        choices=["session-start", "pre", "post"],
        required=True,
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "init":
        print("tatu-hook init: not yet implemented")
        sys.exit(0)

    if args.command == "run":
        print(f"tatu-hook run --event={args.event}: not yet implemented")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Verify it works**

```bash
cd tatu-hook && pip install -e . && tatu-hook --version
```

Expected: `tatu-hook 0.1.0`

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/
git commit -m "feat: scaffold tatu-hook CLI package"
```

---

### Task 11: Rule engine (YAML regex evaluator)

**Files:**
- Create: `tatu-hook/src/tatu_hook/engine.py`
- Create: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write test for rule engine**

```python
# tatu-hook/tests/test_engine.py
import pytest
from tatu_hook.engine import load_yaml_rules, evaluate_rules


SAMPLE_RULE = """id: test-aws-key
info:
  name: Test AWS Key
  severity: critical
  category: secrets

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: strict

detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'

message: "AWS key found"
"""

SAMPLE_WARN_RULE = """id: test-email
info:
  name: Test Email
  severity: warning
  category: pii

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '[a-z]+@example\\.com'

message: "Email found"
"""


def test_load_yaml_rules():
    rules = load_yaml_rules([{"id": "r1", "content": SAMPLE_RULE, "format": "yaml"}])
    assert len(rules) == 1
    assert rules[0]["id"] == "test-aws-key"


def test_evaluate_rules_match_strict_block():
    rules = load_yaml_rules([{"id": "r1", "content": SAMPLE_RULE, "format": "yaml"}])
    results = evaluate_rules(rules, "Write", "config with AKIAIOSFODNN7EXAMPLE in it")
    assert len(results) == 1
    assert results[0]["action"] == "block"
    assert results[0]["mode"] == "strict"


def test_evaluate_rules_no_match():
    rules = load_yaml_rules([{"id": "r1", "content": SAMPLE_RULE, "format": "yaml"}])
    results = evaluate_rules(rules, "Write", "clean content with no secrets")
    assert len(results) == 0


def test_evaluate_rules_matcher_filters():
    rules = load_yaml_rules([{"id": "r1", "content": SAMPLE_RULE, "format": "yaml"}])
    results = evaluate_rules(rules, "Bash", "AKIAIOSFODNN7EXAMPLE")
    assert len(results) == 0  # matcher is Write|Edit, not Bash


def test_evaluate_rules_audit_mode():
    rules = load_yaml_rules([{"id": "r1", "content": SAMPLE_WARN_RULE, "format": "yaml"}])
    results = evaluate_rules(rules, "Write", "contact user@example.com")
    assert len(results) == 1
    assert results[0]["action"] == "warn"
    assert results[0]["mode"] == "audit"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd tatu-hook && python -m pytest tests/test_engine.py -v
```

- [ ] **Step 3: Write rule engine**

```python
# tatu-hook/src/tatu_hook/engine.py
"""Rule evaluation engine for tatu-hook."""
from __future__ import annotations

import re
from typing import Any

import yaml


def load_yaml_rules(raw_rules: list[dict]) -> list[dict]:
    """Parse raw rule dicts (with 'content' field) into evaluable rules."""
    parsed = []
    for raw in raw_rules:
        if raw.get("format") != "yaml":
            continue
        try:
            data = yaml.safe_load(raw["content"])
        except yaml.YAMLError:
            continue
        info = data.get("info", {})
        hook = data.get("hook", {})
        detect = data.get("detect", {})
        patterns = detect.get("patterns", [])
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error:
                continue
        parsed.append({
            "id": data.get("id", raw.get("id", "unknown")),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "category": info.get("category", ""),
            "hook_event": hook.get("event", "PreToolUse"),
            "matcher": hook.get("matcher", ".*"),
            "action": hook.get("action", "log"),
            "mode": hook.get("mode", "audit"),
            "patterns": compiled,
            "message": data.get("message", ""),
        })
    return parsed


def evaluate_rules(
    rules: list[dict],
    tool_name: str,
    content: str,
    hook_event: str = "PreToolUse",
) -> list[dict]:
    """Evaluate content against rules. Returns list of matched rule results."""
    results = []
    for rule in rules:
        if rule["hook_event"] != hook_event:
            continue
        matcher_re = re.compile(rule["matcher"])
        if not matcher_re.search(tool_name):
            continue
        for pattern in rule["patterns"]:
            match = pattern.search(content)
            if match:
                results.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "action": rule["action"],
                    "mode": rule["mode"],
                    "message": rule["message"],
                    "matched": match.group(0)[:100],
                })
                break  # one match per rule is enough
    return results
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd tatu-hook && python -m pytest tests/test_engine.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/engine.py tatu-hook/tests/test_engine.py
git commit -m "feat: add tatu-hook rule evaluation engine"
```

---

### Task 12: Claude Code protocol handler

**Files:**
- Create: `tatu-hook/src/tatu_hook/protocol.py`
- Create: `tatu-hook/tests/test_protocol.py`

- [ ] **Step 1: Write test for protocol handler**

```python
# tatu-hook/tests/test_protocol.py
import json
from tatu_hook.protocol import (
    parse_hook_input,
    format_allow_response,
    format_deny_response,
    format_audit_response,
    extract_content,
)


def test_parse_pre_tool_use():
    inp = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/test.py",
            "content": "secret = 'AKIAIOSFODNN7EXAMPLE'"
        }
    }
    parsed = parse_hook_input(json.dumps(inp))
    assert parsed["hook_event"] == "PreToolUse"
    assert parsed["tool_name"] == "Write"


def test_extract_content_write():
    inp = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/test.py",
            "content": "my_secret = 'foo'"
        }
    }
    content = extract_content(inp)
    assert "my_secret" in content


def test_extract_content_bash():
    inp = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "rm -rf /"
        }
    }
    content = extract_content(inp)
    assert "rm -rf" in content


def test_format_allow():
    resp = format_allow_response("PreToolUse")
    assert "permissionDecision" in str(resp)
    parsed = json.loads(resp)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_format_deny():
    resp = format_deny_response("PreToolUse", "blocked: secret found")
    parsed = json.loads(resp)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "secret found" in parsed["hookSpecificOutput"]["permissionDecisionReason"]


def test_format_audit():
    resp = format_audit_response("PreToolUse", "would block: secret found")
    parsed = json.loads(resp)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "would block" in parsed["hookSpecificOutput"].get("permissionDecisionReason", "")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd tatu-hook && python -m pytest tests/test_protocol.py -v
```

- [ ] **Step 3: Write protocol handler**

```python
# tatu-hook/src/tatu_hook/protocol.py
"""Claude Code hook protocol: stdin parsing and stdout/stderr responses."""
from __future__ import annotations

import json


def parse_hook_input(raw: str) -> dict:
    data = json.loads(raw)
    return {
        "hook_event": data.get("hook_event_name", ""),
        "tool_name": data.get("tool_name", ""),
        "tool_input": data.get("tool_input", {}),
        "tool_response": data.get("tool_response", {}),
        "raw": data,
    }


def extract_content(hook_input: dict) -> str:
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    tool_response = hook_input.get("tool_response", {})
    hook_event = hook_input.get("hook_event_name", "")

    parts = []

    if isinstance(tool_input, dict):
        if tool_name in ("Write", "Edit", "MultiEdit", "Read"):
            content = tool_input.get("content", "")
            if content:
                parts.append(content)
            file_path = tool_input.get("file_path", "")
            if file_path:
                parts.append(file_path)
        elif tool_name == "Bash":
            cmd = tool_input.get("command", "")
            if cmd:
                parts.append(cmd)
        else:
            content = tool_input.get("content", "")
            if content:
                parts.append(content)

    # For PostToolUse, also scan tool_response
    if hook_event == "PostToolUse" and isinstance(tool_response, dict):
        for key in ("stdout", "stderr", "content"):
            val = tool_response.get(key, "")
            if isinstance(val, str) and val.strip():
                parts.append(val)

    return "\n".join(parts)


def format_allow_response(hook_event: str, context: str | None = None) -> str:
    if hook_event == "PreToolUse":
        out: dict = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }
        if context:
            out["hookSpecificOutput"]["permissionDecisionReason"] = context
        return json.dumps(out)
    out = {"hookSpecificOutput": {"hookEventName": hook_event}}
    if context:
        out["hookSpecificOutput"]["additionalContext"] = context
    return json.dumps(out)


def format_deny_response(hook_event: str, reason: str) -> str:
    if hook_event == "PreToolUse":
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
    return json.dumps({
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": hook_event},
    })


def format_audit_response(hook_event: str, context: str) -> str:
    """Audit mode: allow but include context about what would have been blocked."""
    if hook_event == "PreToolUse":
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": context,
            }
        })
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": context,
        }
    })
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd tatu-hook && python -m pytest tests/test_protocol.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/protocol.py tatu-hook/tests/test_protocol.py
git commit -m "feat: add Claude Code protocol handler for tatu-hook"
```

---

### Task 13: Sync client and event reporter

**Files:**
- Create: `tatu-hook/src/tatu_hook/sync.py`
- Create: `tatu-hook/src/tatu_hook/reporter.py`
- Create: `tatu-hook/tests/test_sync.py`

- [ ] **Step 1: Write test for sync client**

```python
# tatu-hook/tests/test_sync.py
import json
import tempfile
import os
from tatu_hook.sync import (
    load_manifest,
    save_manifest,
    save_rules_to_cache,
    load_rules_from_cache,
)


def test_manifest_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest = {
            "version": 5,
            "api_url": "http://localhost:8000",
            "api_key": "tatu_test",
            "updated_at": "2026-03-14T00:00:00Z",
            "rule_count": 10,
        }
        save_manifest(tmpdir, manifest)
        loaded = load_manifest(tmpdir)
        assert loaded["version"] == 5
        assert loaded["api_key"] == "tatu_test"


def test_manifest_missing_returns_defaults():
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest = load_manifest(tmpdir)
        assert manifest["version"] == 0


def test_save_and_load_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        rules = [
            {"id": "r1", "format": "yaml", "content": "id: r1\ninfo:\n  name: R1"},
            {"id": "r2", "format": "yara", "content": "rule r2 {}"},
        ]
        save_rules_to_cache(tmpdir, rules)
        loaded = load_rules_from_cache(tmpdir)
        assert len(loaded) == 2
        assert any(r["id"] == "r1" for r in loaded)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd tatu-hook && python -m pytest tests/test_sync.py -v
```

- [ ] **Step 3: Write sync client**

```python
# tatu-hook/src/tatu_hook/sync.py
"""Rule sync client — downloads rules from Tatu API on SessionStart."""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error


TATU_DIR = os.path.expanduser("~/.tatu")


def ensure_tatu_dir(base: str | None = None) -> str:
    d = base or TATU_DIR
    os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(d, "rules"), exist_ok=True)
    os.makedirs(os.path.join(d, "yara"), exist_ok=True)
    return d


def load_manifest(base: str | None = None) -> dict:
    d = base or TATU_DIR
    path = os.path.join(d, "manifest.json")
    if not os.path.exists(path):
        return {"version": 0, "api_url": "", "api_key": "", "updated_at": "", "rule_count": 0}
    with open(path) as f:
        return json.load(f)


def save_manifest(base: str, manifest: dict) -> None:
    ensure_tatu_dir(base)
    path = os.path.join(base, "manifest.json")
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)


def save_rules_to_cache(base: str, rules: list[dict]) -> None:
    ensure_tatu_dir(base)
    rules_dir = os.path.join(base, "rules")
    yara_dir = os.path.join(base, "yara")

    # Clear existing cached rules
    for d in (rules_dir, yara_dir):
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))

    for rule in rules:
        if rule["format"] == "yara":
            path = os.path.join(yara_dir, f"{rule['id']}.yar")
        else:
            path = os.path.join(rules_dir, f"{rule['id']}.yaml")
        with open(path, "w") as f:
            f.write(rule["content"])


def load_rules_from_cache(base: str | None = None) -> list[dict]:
    d = base or TATU_DIR
    rules = []
    rules_dir = os.path.join(d, "rules")
    yara_dir = os.path.join(d, "yara")

    if os.path.isdir(rules_dir):
        for filename in sorted(os.listdir(rules_dir)):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath) as f:
                content = f.read()
            rule_id = os.path.splitext(filename)[0]
            rules.append({"id": rule_id, "format": "yaml", "content": content})

    if os.path.isdir(yara_dir):
        for filename in sorted(os.listdir(yara_dir)):
            filepath = os.path.join(yara_dir, filename)
            with open(filepath) as f:
                content = f.read()
            rule_id = os.path.splitext(filename)[0]
            rules.append({"id": rule_id, "format": "yara", "content": content})

    return rules


def sync_rules(base: str | None = None) -> list[dict]:
    """Check version and download rules if outdated. Returns loaded rules."""
    d = base or TATU_DIR
    manifest = load_manifest(d)

    api_url = manifest.get("api_url", "")
    api_key = manifest.get("api_key", "")
    local_version = manifest.get("version", 0)

    if not api_url or not api_key:
        return load_rules_from_cache(d)

    try:
        url = f"{api_url}/api/v1/rules/sync?version={local_version}"
        req = urllib.request.Request(url, headers={"X-API-Key": api_key})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return load_rules_from_cache(d)

    if data.get("status") == "up_to_date":
        return load_rules_from_cache(d)

    rules = data.get("rules", [])
    save_rules_to_cache(d, rules)
    save_manifest(d, {
        **manifest,
        "version": data["version"],
        "updated_at": data.get("updated_at", ""),
        "rule_count": len(rules),
    })
    return rules
```

- [ ] **Step 4: Write event reporter**

```python
# tatu-hook/src/tatu_hook/reporter.py
"""Async event reporter — fire-and-forget POST to Tatu API."""
from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error


def report_event(
    api_url: str,
    api_key: str,
    event: dict,
) -> None:
    """Fire-and-forget event report. Runs in a background thread."""
    if not api_url or not api_key:
        return

    def _send():
        try:
            url = f"{api_url}/api/v1/events"
            body = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": api_key,
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except (urllib.error.URLError, OSError):
            pass  # fire-and-forget

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()
```

- [ ] **Step 5: Run tests**

```bash
cd tatu-hook && python -m pytest tests/test_sync.py -v
```

- [ ] **Step 6: Commit**

```bash
git add tatu-hook/src/tatu_hook/sync.py tatu-hook/src/tatu_hook/reporter.py tatu-hook/tests/test_sync.py
git commit -m "feat: add rule sync client and event reporter for tatu-hook"
```

---

### Task 14: Wire up CLI with full hook execution

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`
- Create: `tatu-hook/tests/test_cli.py`

- [ ] **Step 1: Write test for CLI hook execution**

```python
# tatu-hook/tests/test_cli.py
import json
import tempfile
import os
import pytest
from tatu_hook.cli import run_hook
from tatu_hook.sync import save_manifest, save_rules_to_cache


BLOCK_RULE = """id: test-block
info:
  name: Test Block
  severity: critical
  category: secrets
hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: strict
detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'
message: "AWS key detected"
"""

AUDIT_RULE = """id: test-audit
info:
  name: Test Audit
  severity: critical
  category: secrets
hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit
detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'
message: "AWS key detected (audit)"
"""


@pytest.fixture
def tatu_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        save_manifest(tmpdir, {
            "version": 1,
            "api_url": "",
            "api_key": "",
            "updated_at": "",
            "rule_count": 1,
        })
        yield tmpdir


def test_run_hook_strict_block(tatu_dir):
    save_rules_to_cache(tatu_dir, [
        {"id": "test-block", "format": "yaml", "content": BLOCK_RULE},
    ])
    hook_input = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "test.py", "content": "key = 'AKIAIOSFODNN7EXAMPLE'"},
    })
    result = run_hook("pre", hook_input, tatu_dir=tatu_dir)
    assert result["decision"] == "deny"


def test_run_hook_audit_allows(tatu_dir):
    save_rules_to_cache(tatu_dir, [
        {"id": "test-audit", "format": "yaml", "content": AUDIT_RULE},
    ])
    hook_input = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "test.py", "content": "key = 'AKIAIOSFODNN7EXAMPLE'"},
    })
    result = run_hook("pre", hook_input, tatu_dir=tatu_dir)
    assert result["decision"] == "allow"
    assert "audit" in result.get("context", "").lower()


def test_run_hook_no_match(tatu_dir):
    save_rules_to_cache(tatu_dir, [
        {"id": "test-block", "format": "yaml", "content": BLOCK_RULE},
    ])
    hook_input = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "test.py", "content": "clean code here"},
    })
    result = run_hook("pre", hook_input, tatu_dir=tatu_dir)
    assert result["decision"] == "allow"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd tatu-hook && python -m pytest tests/test_cli.py -v
```

- [ ] **Step 3: Update CLI with full hook execution**

```python
# tatu-hook/src/tatu_hook/cli.py
"""Tatu Hook — Claude Code security hook CLI."""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone

from tatu_hook import __version__
from tatu_hook.engine import load_yaml_rules, evaluate_rules
from tatu_hook.protocol import (
    parse_hook_input,
    extract_content,
    format_allow_response,
    format_deny_response,
    format_audit_response,
)
from tatu_hook.sync import (
    load_manifest,
    load_rules_from_cache,
    sync_rules,
    ensure_tatu_dir,
    save_manifest,
)
from tatu_hook.reporter import report_event


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"Tatu Hook v{__version__} — Claude Code security hook"
    )
    p.add_argument("--version", action="version", version=f"tatu-hook {__version__}")
    sub = p.add_subparsers(dest="command")

    init_parser = sub.add_parser("init", help="Initialize tatu-hook configuration")
    init_parser.add_argument("--api-url", required=True, help="Tatu API URL")
    init_parser.add_argument("--api-key", required=True, help="Tatu API key")

    event_parser = sub.add_parser("run", help="Run hook event handler")
    event_parser.add_argument(
        "--event",
        choices=["session-start", "pre", "post"],
        required=True,
    )
    return p


def run_hook(
    event: str,
    raw_input: str,
    tatu_dir: str | None = None,
) -> dict:
    """Core hook logic. Returns a dict with decision and optional context."""
    d = tatu_dir or ensure_tatu_dir()
    manifest = load_manifest(d)

    # Load cached rules
    raw_rules = load_rules_from_cache(d)
    rules = load_yaml_rules(raw_rules)

    # Parse Claude Code input
    parsed = parse_hook_input(raw_input)
    hook_event = "PreToolUse" if event == "pre" else "PostToolUse"
    tool_name = parsed["tool_name"]
    content = extract_content(parsed["raw"])

    # Evaluate rules
    matches = evaluate_rules(rules, tool_name, content, hook_event)

    if not matches:
        return {"decision": "allow", "context": None}

    # Check for strict blocks first
    strict_blocks = [m for m in matches if m["mode"] == "strict" and m["action"] == "block"]
    if strict_blocks:
        hit = strict_blocks[0]
        _report(manifest, hit, hook_event, tool_name, parsed, "blocked")
        return {"decision": "deny", "context": hit["message"]}

    # Check for audit blocks
    audit_blocks = [m for m in matches if m["mode"] == "audit" and m["action"] == "block"]
    if audit_blocks:
        hit = audit_blocks[0]
        _report(manifest, hit, hook_event, tool_name, parsed, "audit_block")
        return {"decision": "allow", "context": f"[AUDIT] {hit['message']}"}

    # Warnings
    warns = [m for m in matches if m["action"] == "warn"]
    if warns:
        hit = warns[0]
        _report(manifest, hit, hook_event, tool_name, parsed, "warning")
        return {"decision": "allow", "context": hit["message"]}

    return {"decision": "allow", "context": None}


def _report(manifest: dict, hit: dict, hook_event: str, tool_name: str, parsed: dict, status: str):
    api_url = manifest.get("api_url", "")
    api_key = manifest.get("api_key", "")
    report_event(api_url, api_key, {
        "hook_name": hit["rule_name"],
        "hook_event": hook_event,
        "severity": hit["severity"],
        "status": status,
        "message": hit["message"],
        "developer": "local",
        "repository": "local",
        "session_id": str(uuid.uuid4())[:8],
        "tool_name": tool_name,
        "metadata": {"rule_id": hit["rule_id"], "matched": hit.get("matched", "")},
    })


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "init":
        d = ensure_tatu_dir()
        save_manifest(d, {
            "version": 0,
            "api_url": args.api_url.rstrip("/"),
            "api_key": args.api_key,
            "updated_at": "",
            "rule_count": 0,
        })
        rules = sync_rules(d)
        print(f"Initialized tatu-hook. Synced {len(rules)} rules to ~/.tatu/")
        print("Add hooks to Claude Code settings. See: tatu-hook --help")
        sys.exit(0)

    if args.command == "run":
        raw_input = sys.stdin.read()

        if args.event == "session-start":
            d = ensure_tatu_dir()
            rules = sync_rules(d)
            sys.stdout.write(format_allow_response("SessionStart",
                f"Tatu: synced {len(rules)} rules"))
            sys.stdout.flush()
            sys.exit(0)

        hook_event = "PreToolUse" if args.event == "pre" else "PostToolUse"
        result = run_hook(args.event, raw_input)

        if result["decision"] == "deny":
            sys.stderr.write(format_deny_response(hook_event, result["context"]))
            sys.stderr.flush()
            sys.exit(2)
        elif result["context"]:
            sys.stdout.write(format_allow_response(hook_event, result["context"]))
            sys.stdout.flush()
            sys.exit(0)
        else:
            sys.stdout.write(format_allow_response(hook_event))
            sys.stdout.flush()
            sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

```bash
cd tatu-hook && python -m pytest tests/ -v
```

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py tatu-hook/tests/test_cli.py
git commit -m "feat: wire up tatu-hook CLI with full hook execution pipeline"
```

---

## Chunk 4: Frontend Rules Page & Audit Badge

### Task 15: Frontend types and API client update

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/lib/api.ts`

- [ ] **Step 1: Add Rule types**

Add to `frontend/src/lib/types.ts`:

```typescript
export interface Rule {
  id: string;
  name: string;
  format: "yaml" | "yara";
  content: string;
  source: "builtin" | "custom";
  enabled: boolean;
  category: string;
  severity: "critical" | "warning" | "info";
  mode: "audit" | "strict";
  action: "block" | "warn" | "log";
  hook_event: string;
  matcher: string;
  version_added: number;
}
```

- [ ] **Step 2: Add Rules API methods**

Add to `frontend/src/lib/api.ts`:

```typescript
getRules: (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams(params).toString();
  return request(`/rules${qs ? `?${qs}` : ""}`);
},
createRule: (body: Record<string, unknown>) =>
  request("/rules", { method: "POST", body: JSON.stringify(body) }),
updateRule: (id: string, body: Record<string, unknown>) =>
  request(`/rules/${id}`, { method: "PUT", body: JSON.stringify(body) }),
deleteRule: (id: string) =>
  request(`/rules/${id}`, { method: "DELETE" }),
```

- [ ] **Step 3: Build frontend to verify**

```bash
docker compose --profile build run --rm frontend-build
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/types.ts frontend/src/lib/api.ts
git commit -m "feat: add Rule types and API methods to frontend"
```

---

### Task 16: Rules page

**Files:**
- Create: `frontend/src/pages/Rules.tsx`
- Modify: `frontend/src/App.tsx` (add route)
- Modify: `frontend/src/components/Sidebar.tsx` (add nav item)

- [ ] **Step 1: Write Rules page**

```tsx
// frontend/src/pages/Rules.tsx
import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import type { Rule } from "../lib/types";
import { PageHeader } from "../components/PageHeader";
import { Panel } from "../components/Panel";
import { SeverityBadge } from "../components/SeverityBadge";

export function Rules() {
  const { data, loading, refetch } = useApi<Rule[]>(
    () => api.getRules() as Promise<Rule[]>,
    [],
  );
  const [filter, setFilter] = useState<string>("all");

  const rules = data ?? [];
  const filtered = filter === "all" ? rules : rules.filter((r) => r.category === filter);
  const categories = [...new Set(rules.map((r) => r.category))].sort();

  return (
    <div>
      <PageHeader title="Rules" />

      {/* Category Filter */}
      <div className="flex gap-2 mb-5 flex-wrap">
        <button
          onClick={() => setFilter("all")}
          className={`px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border transition-colors ${
            filter === "all"
              ? "bg-tatu-accent/20 border-tatu-accent text-tatu-accent"
              : "bg-tatu-surface border-tatu-border text-tatu-text-muted hover:border-tatu-border-hover"
          }`}
        >
          All ({rules.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`px-3 py-1.5 rounded text-[11px] font-semibold uppercase tracking-wider border transition-colors ${
              filter === cat
                ? "bg-tatu-accent/20 border-tatu-accent text-tatu-accent"
                : "bg-tatu-surface border-tatu-border text-tatu-text-muted hover:border-tatu-border-hover"
            }`}
          >
            {cat} ({rules.filter((r) => r.category === cat).length})
          </button>
        ))}
      </div>

      {loading && <p className="text-tatu-text-muted text-sm">Loading...</p>}

      {!loading && (
        <Panel className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-tatu-border">
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Name
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Category
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Severity
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Mode
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Action
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Format
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Source
                </th>
                <th className="text-left text-[10px] text-tatu-text-dim uppercase tracking-wider py-2 px-3">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule) => (
                <tr key={rule.id} className="border-b border-tatu-border/50 hover:bg-tatu-surface-alt/50">
                  <td className="py-2.5 px-3 text-tatu-text font-medium">{rule.name}</td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">{rule.category}</td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                        rule.mode === "strict"
                          ? "bg-tatu-critical/15 text-tatu-critical"
                          : "bg-tatu-info/15 text-tatu-info"
                      }`}
                    >
                      {rule.mode}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-tatu-text-muted uppercase text-[10px]">{rule.action}</td>
                  <td className="py-2.5 px-3 text-tatu-text-muted uppercase text-[10px]">{rule.format}</td>
                  <td className="py-2.5 px-3 text-tatu-text-muted">{rule.source}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                        rule.enabled
                          ? "bg-tatu-accent/15 text-tatu-accent"
                          : "bg-tatu-surface-alt text-tatu-text-dim"
                      }`}
                    >
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Add route in App.tsx**

Add import and route:

```tsx
import { Rules } from "./pages/Rules";
// In Routes:
<Route path="rules" element={<Rules />} />
```

- [ ] **Step 3: Add nav item in Sidebar.tsx**

Add a "Rules" nav item in the Sidebar component (read the file first to find the exact location). Place it after "Hooks" and before "Compliance". Use a shield/document icon or similar.

- [ ] **Step 4: Build and lint**

```bash
docker compose --profile build run --rm frontend-build
docker compose --profile lint run --rm frontend-lint
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/Rules.tsx frontend/src/App.tsx frontend/src/components/Sidebar.tsx
git commit -m "feat: add Rules dashboard page with category filters"
```

---

### Task 17: Audit badge in LiveAlerts and AuditLog

**Files:**
- Modify: `frontend/src/pages/LiveAlerts.tsx`
- Modify: `frontend/src/pages/AuditLog.tsx`

- [ ] **Step 1: Update LiveAlerts severity filters to include audit**

In `frontend/src/pages/LiveAlerts.tsx`:

Update `SEVERITY_FILTERS` to also allow filtering by `audit_block` status. Add an "audit" filter button that filters events where `status === "audit_block"`.

- [ ] **Step 2: Update AuditLog status labels**

In `frontend/src/pages/AuditLog.tsx`, add to `STATUS_LABELS` and `STATUS_STYLES`:

```typescript
const STATUS_LABELS: Record<string, string> = {
  blocked: "DENY",
  warning: "WARN",
  allowed: "ALLOW",
  clean: "PASS",
  audit_block: "AUDIT",
};

const STATUS_STYLES: Record<string, string> = {
  DENY: "bg-tatu-critical/15 text-tatu-critical",
  WARN: "bg-tatu-warn/15 text-tatu-warn",
  ALLOW: "bg-tatu-accent/15 text-tatu-accent",
  PASS: "bg-tatu-accent/15 text-tatu-accent",
  AUDIT: "bg-tatu-info/15 text-tatu-info",
};
```

- [ ] **Step 3: Build and lint**

```bash
docker compose --profile build run --rm frontend-build
docker compose --profile lint run --rm frontend-lint
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/pages/LiveAlerts.tsx frontend/src/pages/AuditLog.tsx
git commit -m "feat: add AUDIT badge and filter for audit_block events"
```

---

### Task 18: Full integration verification

- [ ] **Step 1: Run all backend tests**

```bash
docker compose --profile test run --rm test -v
```

Expected: All tests PASS

- [ ] **Step 2: Build frontend**

```bash
docker compose --profile build run --rm frontend-build
```

Expected: Build succeeds

- [ ] **Step 3: Lint frontend**

```bash
docker compose --profile lint run --rm frontend-lint
```

Expected: No errors

- [ ] **Step 4: Run tatu-hook tests**

```bash
cd tatu-hook && python -m pytest tests/ -v
```

Expected: All tests PASS

- [ ] **Step 5: Smoke test**

Start services and verify:
1. Rules page loads with built-in rules
2. Category filters work
3. Mode badges show (audit/strict)
4. Audit events show AUDIT badge in Audit Log

```bash
make dev
```

- [ ] **Step 6: Final commit if adjustments needed**

```bash
git add -A && git commit -m "fix: address integration issues from smoke test"
```
