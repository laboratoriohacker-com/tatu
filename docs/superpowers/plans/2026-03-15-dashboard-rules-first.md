# Dashboard Rules-First Refactor

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hooks-table-based dashboard with rules-table-based data so all stats, compliance, and hook performance reflect real rule definitions and real events.

**Architecture:** The `hooks` table is retired as the source of truth. The `rules` table (loaded from YAML files on startup) becomes the single source for hook names, categories, compliance mappings, and matchers. Backend endpoints are rewritten to query `rules` + `events`. A new alert detail sidebar is added to the frontend.

**Tech Stack:** FastAPI, SQLAlchemy async, Pydantic v2, React 18 + TypeScript, Tailwind CSS

---

## File Structure

### Backend changes
- **Modify:** `backend/app/models/rule.py` — add `compliance_mappings` JSON column
- **Modify:** `backend/app/services/rule_loader.py` — parse `info.compliance` from YAML into `compliance_mappings`
- **Modify:** `backend/app/services/stats_service.py` — fix `secrets_caught` to count by category instead of hardcoded hook name
- **Rewrite:** `backend/app/routers/hooks.py` — query `rules` table + `events` instead of `hooks` table
- **Rewrite:** `backend/app/routers/compliance.py` — compute compliance from `rules.compliance_mappings` instead of `hooks`
- **Modify:** `backend/app/schemas/hook.py` — update `HookWithStats` to use `str` id (rule id) instead of `UUID`
- **Create:** `backend/app/schemas/alert_detail.py` — schema for single event detail
- **Modify:** `backend/app/routers/alerts.py` — add `GET /alerts/{id}` endpoint
- **Modify:** `backend/tests/` — update tests

### Frontend changes
- **Create:** `frontend/src/components/AlertDetail.tsx` — right sidebar for alert detail
- **Modify:** `frontend/src/pages/LiveAlerts.tsx` — add click-to-open detail sidebar
- **Modify:** `frontend/src/pages/Overview.tsx` — add click-to-open detail on recent alerts
- **Modify:** `frontend/src/lib/types.ts` — update `HookWithStats.id` to `string`
- **Modify:** `frontend/src/lib/api.ts` — add `getAlert(id)` method

### Cleanup
- **Delete seed dependency:** `backend/app/seed.py` is no longer needed for hooks (keep file but remove from startup if used)

---

## Chunk 1: Backend — Rules as Source of Truth

### Task 1: Add compliance_mappings to Rule model

**Files:**
- Modify: `backend/app/models/rule.py`

- [ ] **Step 1: Add compliance_mappings column**

In `backend/app/models/rule.py`, add a JSON column after `version_added`:

```python
from sqlalchemy import String, Text, Boolean, Integer, JSON
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
    compliance_mappings: Mapped[list] = mapped_column(JSON, default=list)
```

- [ ] **Step 2: Restart backend to apply schema change**

Run: `docker compose restart backend`

- [ ] **Step 3: Commit**

```bash
git add backend/app/models/rule.py
git commit -m "feat: add compliance_mappings JSON column to Rule model"
```

---

### Task 2: Parse compliance from YAML rules

**Files:**
- Modify: `backend/app/services/rule_loader.py:47-60`

- [ ] **Step 1: Update parse_yaml_rule to extract compliance**

In `backend/app/services/rule_loader.py`, add `compliance_mappings` to the returned dict:

```python
    return {
        "id": data["id"],
        "name": info.get("name", data["id"]),
        "format": "yaml",
        "content": content,
        "enabled": True,
        "category": info.get("category", ""),
        "severity": info.get("severity", "info"),
        "mode": hook.get("mode", "audit"),
        "action": hook.get("action", "log"),
        "hook_event": ",".join(hook["events"]) if "events" in hook else hook.get("event", "PreToolUse"),
        "matcher": hook.get("matcher", "*"),
        "version_added": 1,
        "compliance_mappings": info.get("compliance", []),
    }
```

Also update `parse_yara_rule` (around line 113-126) to include:
```python
        "compliance_mappings": [],
```

- [ ] **Step 2: Restart backend and verify rules load with compliance data**

Run: `docker compose restart backend`

Verify: `curl -s http://localhost:8000/api/v1/rules?category=secrets | python3 -c "import sys,json; rules=json.load(sys.stdin); print(rules[0].get('name'), rules[0].get('compliance_mappings', 'MISSING'))"`

Expected: Rule name followed by a list of compliance controls (not "MISSING")

- [ ] **Step 3: Commit**

```bash
git add backend/app/services/rule_loader.py
git commit -m "feat: parse compliance mappings from YAML rule info section"
```

---

### Task 3: Fix secrets_caught stat

**Files:**
- Modify: `backend/app/services/stats_service.py:22-24`

The current code counts `Event.hook_name == "Secrets Leak Prevention"` but tatu-hook sends rule names like "AWS Access Key". Fix to count by category.

- [ ] **Step 1: Update secrets_caught query**

In `backend/app/services/stats_service.py`, change the `secrets_caught` aggregation (lines 22-24). We need to join with the rules table to filter by category, or use a subquery. The simplest approach: query events whose `hook_name` matches any rule with `category == "secrets"`.

Replace the entire `get_overview_stats` function:

```python
async def get_overview_stats(db: AsyncSession, period: str = "24h") -> dict:
    from app.models.rule import Rule

    start = _period_start(period)

    # Get all secret rule names
    secrets_result = await db.execute(
        select(Rule.name).where(Rule.category == "secrets", Rule.enabled == True)
    )
    secret_names = [r for (r,) in secrets_result.all()]

    result = await db.execute(
        select(
            func.count(Event.id).label("total_events"),
            func.sum(case((Event.status.in_(["blocked", "audit_block"]), 1), else_=0)).label("total_blocks"),
            func.sum(case(
                (Event.hook_name.in_(secret_names), 1), else_=0
            )).label("secrets_caught"),
        ).where(Event.timestamp >= start)
    )
    row = result.one()
    total_events = row.total_events or 0
    total_blocks = row.total_blocks or 0
    secrets_caught = row.secrets_caught or 0

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
```

Note: also counts `audit_block` status in `total_blocks` since audit mode events are security-relevant.

- [ ] **Step 2: Restart and verify**

Run: `docker compose restart backend`

- [ ] **Step 3: Commit**

```bash
git add backend/app/services/stats_service.py
git commit -m "fix: secrets_caught counts events by rule category instead of hardcoded hook name"
```

---

### Task 4: Rewrite hooks endpoint to use rules table

**Files:**
- Modify: `backend/app/routers/hooks.py`
- Modify: `backend/app/schemas/hook.py`

- [ ] **Step 1: Update HookWithStats schema**

Replace `backend/app/schemas/hook.py`:

```python
from pydantic import BaseModel


class HookWithStats(BaseModel):
    id: str
    name: str
    category: str
    hook_event: str
    matcher: str
    enabled: bool
    compliance_mappings: list[str]
    triggers: int = 0
    blocks: int = 0
    block_rate: str = "0%"
```

Key change: `id` is now `str` (rule id like "aws-access-key") instead of `UUID`.

- [ ] **Step 2: Rewrite hooks router to query rules table**

Replace `backend/app/routers/hooks.py`:

```python
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from datetime import datetime, timezone, timedelta

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.rule import Rule
from app.models.event import Event
from app.schemas.hook import HookWithStats

router = APIRouter(prefix="/api/v1", tags=["hooks"], dependencies=[Depends(require_dashboard_auth)])


@router.get("/hooks", response_model=list[HookWithStats])
async def list_hooks(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))

    rules_result = await db.execute(select(Rule))
    rules = rules_result.scalars().all()

    result = []
    for rule in rules:
        stats = await db.execute(
            select(
                func.count(Event.id).label("triggers"),
                func.sum(case((Event.status.in_(["blocked", "audit_block"]), 1), else_=0)).label("blocks"),
            ).where(Event.hook_name == rule.name, Event.timestamp >= start)
        )
        row = stats.one()
        triggers = row.triggers or 0
        blocks = row.blocks or 0
        rate = f"{(blocks / triggers * 100):.1f}" if triggers > 0 else "0"

        result.append(HookWithStats(
            id=rule.id, name=rule.name, category=rule.category,
            hook_event=rule.hook_event, matcher=rule.matcher,
            enabled=rule.enabled, compliance_mappings=rule.compliance_mappings,
            triggers=triggers, blocks=blocks, block_rate=rate,
        ))
    return result
```

Key changes:
- Queries `Rule` instead of `Hook`
- Uses `rule.compliance_mappings` (from YAML)
- `block_rate` returns number string without `%` (frontend appends it)
- Counts `audit_block` status as blocks

- [ ] **Step 3: Restart and verify**

Run: `docker compose restart backend`
Verify: `curl -s http://localhost:8000/api/v1/hooks?period=24h` (after login, or temporarily remove auth for testing)

- [ ] **Step 4: Commit**

```bash
git add backend/app/routers/hooks.py backend/app/schemas/hook.py
git commit -m "feat: hooks endpoint queries rules table instead of hooks table"
```

---

### Task 5: Rewrite compliance endpoint to use rules table

**Files:**
- Modify: `backend/app/routers/compliance.py`

- [ ] **Step 1: Rewrite compliance router**

Replace `backend/app/routers/compliance.py`:

```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.rule import Rule
from app.schemas.stats import ComplianceResponse, ComplianceFramework, ComplianceMapping

router = APIRouter(prefix="/api/v1", tags=["compliance"], dependencies=[Depends(require_dashboard_auth)])

FRAMEWORK_TOTALS = {
    "SOC2": 14,
    "LGPD": 8,
    "CPS234": 12,
    "ISO 27001": 18,
    "PCI DSS": 12,
    "NIST CSF": 10,
    "FedRAMP": 10,
    "DORA": 8,
    "GDPR": 8,
}


@router.get("/compliance", response_model=ComplianceResponse)
async def get_compliance(db: AsyncSession = Depends(get_db)):
    rules_result = await db.execute(select(Rule).where(Rule.enabled == True))
    rules = rules_result.scalars().all()

    framework_coverage: dict[str, set[str]] = {fw: set() for fw in FRAMEWORK_TOTALS}
    mappings: list[ComplianceMapping] = []

    for rule in rules:
        rule_controls = rule.compliance_mappings or []
        for control in rule_controls:
            for fw in FRAMEWORK_TOTALS:
                if control.startswith(fw) or (fw == "ISO 27001" and control.startswith("ISO")):
                    framework_coverage[fw].add(control)
        if rule_controls:
            mappings.append(ComplianceMapping(hook=rule.name, maps=", ".join(rule_controls)))

    frameworks = []
    for fw, total in FRAMEWORK_TOTALS.items():
        covered = len(framework_coverage[fw])
        pct = min(round((covered / total) * 100), 100) if total > 0 else 0
        status = "compliant" if pct >= 90 else "partial" if pct >= 50 else "low"
        frameworks.append(ComplianceFramework(
            framework=fw, controls=total, covered=covered,
            status=status, percentage=pct,
        ))

    return ComplianceResponse(frameworks=frameworks, mappings=mappings)
```

Key changes:
- Uses `Rule` table instead of `Hook` table
- Added new frameworks: PCI DSS, NIST CSF, FedRAMP, DORA, GDPR (all referenced in YAML rules)
- `compliance_mappings` comes from the YAML `info.compliance` field

- [ ] **Step 2: Restart and verify**

Run: `docker compose restart backend`

- [ ] **Step 3: Commit**

```bash
git add backend/app/routers/compliance.py
git commit -m "feat: compliance endpoint computes coverage from rules table"
```

---

## Chunk 2: Backend — Alert Detail Endpoint

### Task 6: Add single alert detail endpoint

**Files:**
- Modify: `backend/app/routers/alerts.py`

- [ ] **Step 1: Add GET /alerts/{id} endpoint**

Add to `backend/app/routers/alerts.py`:

```python
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.event import Event
from app.schemas.stats import PaginatedResponse
from app.schemas.event import EventResponse
from app.services.event_service import get_alerts

router = APIRouter(
    prefix="/api/v1",
    tags=["alerts"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/alerts/{alert_id}", response_model=EventResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    event = await db.get(Event, alert_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return event


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

Note: The `/alerts/{alert_id}` route MUST be defined before `/alerts` to avoid FastAPI matching `{alert_id}` as a query.

- [ ] **Step 2: Restart and verify**

Run: `docker compose restart backend`

- [ ] **Step 3: Commit**

```bash
git add backend/app/routers/alerts.py
git commit -m "feat: add GET /alerts/{id} endpoint for alert detail"
```

---

## Chunk 3: Frontend — Alert Detail Sidebar

### Task 7: Add API method and types

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`

- [ ] **Step 1: Add getAlert to API client**

In `frontend/src/lib/api.ts`, add after the `getAlerts` method:

```typescript
  getAlert: (id: string) =>
    request(`/alerts/${id}`),
```

- [ ] **Step 2: Update HookWithStats type**

In `frontend/src/lib/types.ts`, change `HookWithStats.id` from `string` to match the new rule-based id:

No change needed — `id` is already `string`. The UUID was only in the Pydantic schema which we already fixed.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat: add getAlert API method for alert detail"
```

---

### Task 8: Create AlertDetail sidebar component

**Files:**
- Create: `frontend/src/components/AlertDetail.tsx`

- [ ] **Step 1: Create the component**

Create `frontend/src/components/AlertDetail.tsx`:

```tsx
import type { Event } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { StatusDot } from "./StatusDot";
import { Panel } from "./Panel";

interface AlertDetailProps {
  alert: Event;
  onClose: () => void;
}

export function AlertDetail({ alert, onClose }: AlertDetailProps) {
  const meta = alert.metadata_ ?? {};

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Sidebar */}
      <div className="relative w-full max-w-md bg-tatu-bg border-l border-tatu-border overflow-y-auto">
        <div className="p-5">
          {/* Header */}
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-sm font-semibold text-tatu-text">Alert Detail</h2>
            <button
              onClick={onClose}
              className="text-tatu-text-dim hover:text-tatu-text text-lg leading-none"
            >
              &times;
            </button>
          </div>

          {/* Status & Severity */}
          <div className="flex items-center gap-3 mb-4">
            <StatusDot status={alert.status} />
            <SeverityBadge severity={alert.severity} />
            <span className="text-[10px] text-tatu-text-dim uppercase tracking-wider">
              {alert.status}
            </span>
          </div>

          {/* Message */}
          <Panel className="mb-4">
            <p className="text-sm text-tatu-text">{alert.message}</p>
          </Panel>

          {/* Details Grid */}
          <div className="space-y-3 text-xs mb-4">
            <DetailRow label="Hook" value={alert.hook_name} />
            <DetailRow label="Event" value={alert.hook_event} />
            <DetailRow label="Developer" value={alert.developer} />
            <DetailRow label="Repository" value={alert.repository} />
            <DetailRow label="Tool" value={alert.tool_name ?? "—"} />
            <DetailRow label="Session" value={alert.session_id} mono />
            <DetailRow
              label="Time"
              value={new Date(alert.timestamp).toLocaleString()}
            />
          </div>

          {/* Metadata */}
          {Object.keys(meta).length > 0 && (
            <Panel>
              <h3 className="text-[10px] text-tatu-text-dim uppercase tracking-wider mb-2">
                Metadata
              </h3>
              <div className="space-y-1.5">
                {Object.entries(meta).map(([key, value]) => (
                  <div key={key} className="flex justify-between text-xs">
                    <span className="text-tatu-text-muted">{key}</span>
                    <span className="text-tatu-text font-mono text-[11px] max-w-[60%] truncate text-right">
                      {String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between items-start">
      <span className="text-tatu-text-dim">{label}</span>
      <span
        className={`text-tatu-text text-right max-w-[65%] truncate ${mono ? "font-mono text-[11px]" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/AlertDetail.tsx
git commit -m "feat: add AlertDetail sidebar component"
```

---

### Task 9: Integrate sidebar into LiveAlerts page

**Files:**
- Modify: `frontend/src/pages/LiveAlerts.tsx`

- [ ] **Step 1: Add selected alert state and sidebar**

Update `frontend/src/pages/LiveAlerts.tsx`:

1. Add import at top:
```typescript
import { AlertDetail } from "../components/AlertDetail";
```

2. Add state after the existing `useState` calls:
```typescript
const [selected, setSelected] = useState<Event | null>(null);
```

3. Make each alert card clickable — replace the `<Panel key={event.id}>` line with:
```tsx
<Panel key={event.id} className="cursor-pointer hover:border-tatu-accent/30 transition-colors" onClick={() => setSelected(event)}>
```

4. Add the sidebar before the closing `</div>` of the return:
```tsx
{selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} />}
```

- [ ] **Step 2: Verify in browser**

Open Live Alerts page, click an alert card — sidebar should appear on the right.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/LiveAlerts.tsx
git commit -m "feat: add alert detail sidebar to LiveAlerts page"
```

---

### Task 10: Add alert detail to Overview recent alerts

**Files:**
- Modify: `frontend/src/pages/Overview.tsx`

- [ ] **Step 1: Add selected state and sidebar to Overview**

1. Add imports:
```typescript
import { useState } from "react";
import { AlertDetail } from "../components/AlertDetail";
```

2. Add state inside the `Overview` component:
```typescript
const [selected, setSelected] = useState<Event | null>(null);
```

3. Make each recent alert row clickable — add `onClick` and cursor styling to the alert `<div>`:
```tsx
<div
  key={alert.id}
  onClick={() => setSelected(alert)}
  className="flex items-center gap-3 text-xs py-2 border-b border-tatu-border last:border-0 cursor-pointer hover:bg-tatu-surface-alt/30 transition-colors"
>
```

4. Add sidebar before closing `</div>`:
```tsx
{selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} />}
```

- [ ] **Step 2: Verify in browser**

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Overview.tsx
git commit -m "feat: add alert detail sidebar to Overview recent alerts"
```

---

## Chunk 4: Frontend — Update types and fix block_rate display

### Task 11: Fix block_rate display on Hooks page

**Files:**
- Modify: `frontend/src/pages/Hooks.tsx:84`
- Modify: `frontend/src/pages/Overview.tsx:94`

The backend now returns `block_rate` as a number string without `%` suffix. The frontend already appends `%`. Verify this doesn't double-append.

- [ ] **Step 1: Verify block_rate format**

Check `Hooks.tsx:84`: `{hook.block_rate}%` — this is correct if backend sends `"45.3"`.
Check `Overview.tsx:94`: `{hook.block_rate}%` — same.

The old backend sent `"45.3%"` which would have displayed as `"45.3%%"`. The new backend sends `"45.3"` so the display is now correct. No code change needed.

- [ ] **Step 2: Build frontend to verify no type errors**

Run: `docker compose exec frontend npm run build`

- [ ] **Step 3: Commit (if any changes were needed)**

---

## Chunk 5: Cleanup and Integration Test

### Task 12: Run full integration test

- [ ] **Step 1: Restart all services**

Run: `docker compose restart`

- [ ] **Step 2: Trigger test events**

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"test.py","content":"key = AKIAIOSFODNN7EXAMPLE"}}' | tatu-hook run --event pre
```

- [ ] **Step 3: Verify dashboard pages**

1. Overview: "Secrets Caught" should show >= 1
2. Overview: "Top Hooks by Block Rate" should show rule names
3. Hooks page: should list all rules with triggers/blocks from real events
4. Compliance page: should show coverage for all frameworks (SOC2, LGPD, PCI DSS, NIST, etc.)
5. Live Alerts: click an alert — detail sidebar should open

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: integration test verification complete"
```
