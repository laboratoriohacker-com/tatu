from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth, require_role
from app.database import get_db
from app.schemas.rule import (
    RuleCreate,
    RuleResponse,
    RuleSyncItem,
    RuleSyncResponse,
    RuleSyncUpToDate,
    RuleUpdate,
)
from app.services import rule_service

# Sync router — no auth required so the tatu-hook CLI can call it freely
sync_router = APIRouter(prefix="/api/v1/rules", tags=["rules-sync"])

# CRUD router — dashboard auth required for reads; admin/editor required for writes
router = APIRouter(
    prefix="/api/v1/rules",
    tags=["rules"],
)


@sync_router.get("/sync", response_model=RuleSyncResponse | RuleSyncUpToDate)
async def sync_rules(
    version: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Return enabled rules if client version is outdated, otherwise up_to_date."""
    current = await rule_service.get_current_version(db)
    if version >= current:
        return RuleSyncUpToDate(version=current)

    rules = await rule_service.get_enabled_rules(db)
    return RuleSyncResponse(
        version=current,
        updated_at=datetime.now(timezone.utc).isoformat(),
        rules=[RuleSyncItem(id=r.id, format=r.format, content=r.content) for r in rules],
    )


@router.get("", response_model=list[RuleResponse],
            dependencies=[Depends(require_dashboard_auth)])
async def list_rules(
    category: str | None = Query(None),
    source: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List all rules with optional filters."""
    return await rule_service.list_rules(db, category=category, source=source)


@router.get("/{rule_id}", response_model=RuleResponse,
            dependencies=[Depends(require_dashboard_auth)])
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a single rule by ID."""
    from app.models.rule import Rule
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_role("admin", "editor"))])
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a custom rule."""
    return await rule_service.create_rule(db, body)


@router.post("/{rule_id}/clone", response_model=RuleResponse,
             dependencies=[Depends(require_role("admin", "editor"))])
async def clone_rule_to_custom(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Clone a built-in rule to a custom rule (makes it fully editable)."""
    rule = await rule_service.clone_to_custom(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse,
            dependencies=[Depends(require_role("admin", "editor"))])
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an existing rule. Returns 404 if not found."""
    rule = await rule_service.update_rule(db, rule_id, body)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_role("admin", "editor"))])
async def disable_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Disable (soft-delete) a rule. Returns 404 if not found."""
    rule = await rule_service.disable_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
