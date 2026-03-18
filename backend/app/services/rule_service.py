from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.rule import Rule
from app.models.rule_version import RuleVersion
from app.schemas.rule import RuleCreate, RuleUpdate


async def get_current_version(db: AsyncSession) -> int:
    """Gets current version from RuleVersion table, initializing to 1 if not exists."""
    result = await db.get(RuleVersion, 1)
    if result is None:
        rv = RuleVersion(id=1, version=1)
        db.add(rv)
        await db.commit()
        await db.refresh(rv)
        return rv.version
    return result.version


async def bump_version(db: AsyncSession) -> int:
    """Increments version and returns the new value."""
    result = await db.get(RuleVersion, 1)
    if result is None:
        rv = RuleVersion(id=1, version=2)
        db.add(rv)
        await db.commit()
        await db.refresh(rv)
        return rv.version
    result.version += 1
    await db.commit()
    await db.refresh(result)
    return result.version


async def create_rule(db: AsyncSession, body: RuleCreate) -> Rule:
    """Creates a custom rule and bumps the global version."""
    new_version = await bump_version(db)
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
        version_added=new_version,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(db: AsyncSession, rule_id: str, body: RuleUpdate) -> Rule | None:
    """Updates rule fields and bumps the global version. Returns None if not found."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        return None

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    await bump_version(db)
    await db.commit()
    await db.refresh(rule)
    return rule


async def disable_rule(db: AsyncSession, rule_id: str) -> Rule | None:
    """Sets enabled=False on a rule and bumps the global version. Returns None if not found."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        return None

    rule.enabled = False
    await bump_version(db)
    await db.commit()
    await db.refresh(rule)
    return rule


async def list_rules(
    db: AsyncSession,
    category: str | None = None,
    source: str | None = None,
) -> list[Rule]:
    """List all rules with optional filters by category and/or source."""
    stmt = select(Rule)
    if category is not None:
        stmt = stmt.where(Rule.category == category)
    if source is not None:
        stmt = stmt.where(Rule.source == source)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_enabled_rules(db: AsyncSession) -> list[Rule]:
    """Returns all enabled rules (used by the sync endpoint)."""
    stmt = select(Rule).where(Rule.enabled == True)  # noqa: E712
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def clone_to_custom(db: AsyncSession, rule_id: str) -> Rule | None:
    """Convert a built-in rule to a custom rule so it becomes fully editable."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        return None
    rule.source = "custom"
    await bump_version(db)
    await db.commit()
    await db.refresh(rule)
    return rule


async def upsert_builtin_rule(db: AsyncSession, rule_data: dict) -> None:
    """Upsert a built-in rule. Only updates if the existing rule has source='builtin'.

    Preserves user-configurable fields (mode, action, enabled) so that dashboard
    edits survive container restarts.
    """
    # Fields that users can change via the dashboard — never overwrite these on existing rules
    _USER_CONFIGURABLE = {"mode", "action", "enabled"}

    existing = await db.get(Rule, rule_data["id"])
    if existing is None:
        rule = Rule(**rule_data, source="builtin")
        db.add(rule)
    elif existing.source == "builtin":
        for field, value in rule_data.items():
            if field != "id" and field not in _USER_CONFIGURABLE:
                setattr(existing, field, value)
    await db.commit()
