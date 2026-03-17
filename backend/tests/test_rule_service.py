import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.models import Base
from app.models.rule import Rule
from app.schemas.rule import RuleCreate, RuleUpdate
from app.services.rule_service import (
    get_current_version,
    bump_version,
    create_rule,
    update_rule,
    disable_rule,
    list_rules,
    get_enabled_rules,
    upsert_builtin_rule,
)


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


def make_rule_create(**overrides) -> RuleCreate:
    defaults = dict(
        id="test-rule-v1",
        name="Test Rule",
        format="yaml",
        content="rules:\n  - id: test\n    pattern: TEST",
        category="security",
        severity="critical",
        mode="strict",
        action="block",
        hook_event="PreToolUse",
        matcher="Bash|Write",
    )
    defaults.update(overrides)
    return RuleCreate(**defaults)


# ---------------------------------------------------------------------------
# Version management
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_current_version_initializes_to_1(db_session: AsyncSession):
    version = await get_current_version(db_session)
    assert version == 1


@pytest.mark.asyncio
async def test_get_current_version_idempotent(db_session: AsyncSession):
    v1 = await get_current_version(db_session)
    v2 = await get_current_version(db_session)
    assert v1 == v2 == 1


@pytest.mark.asyncio
async def test_bump_version_increments(db_session: AsyncSession):
    await get_current_version(db_session)  # initialize to 1
    new_version = await bump_version(db_session)
    assert new_version == 2


@pytest.mark.asyncio
async def test_bump_version_increments_multiple_times(db_session: AsyncSession):
    await get_current_version(db_session)
    v2 = await bump_version(db_session)
    v3 = await bump_version(db_session)
    assert v2 == 2
    assert v3 == 3


# ---------------------------------------------------------------------------
# create_rule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_rule_sets_source_custom(db_session: AsyncSession):
    body = make_rule_create()
    rule = await create_rule(db_session, body)
    assert rule.source == "custom"


@pytest.mark.asyncio
async def test_create_rule_stores_fields(db_session: AsyncSession):
    body = make_rule_create()
    rule = await create_rule(db_session, body)
    assert rule.id == "test-rule-v1"
    assert rule.name == "Test Rule"
    assert rule.format == "yaml"
    assert rule.category == "security"
    assert rule.severity == "critical"
    assert rule.mode == "strict"
    assert rule.action == "block"
    assert rule.hook_event == "PreToolUse"
    assert rule.matcher == "Bash|Write"
    assert rule.enabled is True


@pytest.mark.asyncio
async def test_create_rule_bumps_version(db_session: AsyncSession):
    initial = await get_current_version(db_session)
    assert initial == 1
    body = make_rule_create()
    rule = await create_rule(db_session, body)
    assert rule.version_added == 2
    current = await get_current_version(db_session)
    assert current == 2


# ---------------------------------------------------------------------------
# list_rules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_rules_returns_created_rules(db_session: AsyncSession):
    body1 = make_rule_create(id="rule-1", name="Rule 1")
    body2 = make_rule_create(id="rule-2", name="Rule 2")
    await create_rule(db_session, body1)
    await create_rule(db_session, body2)

    rules = await list_rules(db_session)
    assert len(rules) == 2
    ids = {r.id for r in rules}
    assert ids == {"rule-1", "rule-2"}


@pytest.mark.asyncio
async def test_list_rules_empty(db_session: AsyncSession):
    rules = await list_rules(db_session)
    assert rules == []


@pytest.mark.asyncio
async def test_list_rules_filters_by_category(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create(id="sec-rule", category="security"))
    await create_rule(db_session, make_rule_create(id="comp-rule", category="compliance"))

    security_rules = await list_rules(db_session, category="security")
    assert len(security_rules) == 1
    assert security_rules[0].id == "sec-rule"

    compliance_rules = await list_rules(db_session, category="compliance")
    assert len(compliance_rules) == 1
    assert compliance_rules[0].id == "comp-rule"


@pytest.mark.asyncio
async def test_list_rules_filters_by_source(db_session: AsyncSession):
    # custom rule via create_rule
    await create_rule(db_session, make_rule_create(id="custom-rule"))

    # builtin rule via upsert
    await upsert_builtin_rule(db_session, {
        "id": "builtin-rule",
        "name": "Builtin Rule",
        "format": "yaml",
        "content": "content",
        "category": "security",
        "severity": "critical",
        "mode": "strict",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "*",
        "version_added": 1,
    })

    custom_rules = await list_rules(db_session, source="custom")
    assert len(custom_rules) == 1
    assert custom_rules[0].id == "custom-rule"

    builtin_rules = await list_rules(db_session, source="builtin")
    assert len(builtin_rules) == 1
    assert builtin_rules[0].id == "builtin-rule"


# ---------------------------------------------------------------------------
# get_enabled_rules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_enabled_rules_returns_only_enabled(db_session: AsyncSession):
    rule1 = await create_rule(db_session, make_rule_create(id="enabled-rule"))
    rule2 = await create_rule(db_session, make_rule_create(id="disabled-rule"))
    await disable_rule(db_session, rule2.id)

    enabled = await get_enabled_rules(db_session)
    ids = {r.id for r in enabled}
    assert rule1.id in ids
    assert rule2.id not in ids


@pytest.mark.asyncio
async def test_get_enabled_rules_all_enabled(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create(id="rule-a"))
    await create_rule(db_session, make_rule_create(id="rule-b"))

    enabled = await get_enabled_rules(db_session)
    assert len(enabled) == 2


# ---------------------------------------------------------------------------
# update_rule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_rule_modifies_fields(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create())
    body = RuleUpdate(name="Updated Name", action="warn")
    updated = await update_rule(db_session, "test-rule-v1", body)

    assert updated is not None
    assert updated.name == "Updated Name"
    assert updated.action == "warn"
    # unchanged fields
    assert updated.category == "security"
    assert updated.severity == "critical"


@pytest.mark.asyncio
async def test_update_rule_bumps_version(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create())
    version_before = await get_current_version(db_session)
    await update_rule(db_session, "test-rule-v1", RuleUpdate(name="New Name"))
    version_after = await get_current_version(db_session)
    assert version_after == version_before + 1


@pytest.mark.asyncio
async def test_update_rule_returns_none_for_missing(db_session: AsyncSession):
    result = await update_rule(db_session, "nonexistent", RuleUpdate(name="X"))
    assert result is None


@pytest.mark.asyncio
async def test_update_rule_partial_update(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create())
    updated = await update_rule(db_session, "test-rule-v1", RuleUpdate(mode="audit"))
    assert updated is not None
    assert updated.mode == "audit"
    assert updated.name == "Test Rule"  # unchanged


# ---------------------------------------------------------------------------
# disable_rule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disable_rule_sets_enabled_false(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create())
    disabled = await disable_rule(db_session, "test-rule-v1")

    assert disabled is not None
    assert disabled.enabled is False


@pytest.mark.asyncio
async def test_disable_rule_bumps_version(db_session: AsyncSession):
    await create_rule(db_session, make_rule_create())
    version_before = await get_current_version(db_session)
    await disable_rule(db_session, "test-rule-v1")
    version_after = await get_current_version(db_session)
    assert version_after == version_before + 1


@pytest.mark.asyncio
async def test_disable_rule_returns_none_for_missing(db_session: AsyncSession):
    result = await disable_rule(db_session, "nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# upsert_builtin_rule
# ---------------------------------------------------------------------------

def builtin_data(**overrides) -> dict:
    defaults = {
        "id": "builtin-secrets-v1",
        "name": "Secrets Detection",
        "format": "yaml",
        "content": "rules:\n  - id: secrets\n    pattern: SECRET",
        "category": "security",
        "severity": "critical",
        "mode": "strict",
        "action": "block",
        "hook_event": "PreToolUse",
        "matcher": "Bash|Write|Edit",
        "version_added": 1,
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.asyncio
async def test_upsert_builtin_rule_creates_new(db_session: AsyncSession):
    await upsert_builtin_rule(db_session, builtin_data())

    from sqlalchemy import select
    result = await db_session.execute(select(Rule).where(Rule.id == "builtin-secrets-v1"))
    rule = result.scalar_one_or_none()
    assert rule is not None
    assert rule.source == "builtin"
    assert rule.name == "Secrets Detection"


@pytest.mark.asyncio
async def test_upsert_builtin_rule_updates_existing_builtin(db_session: AsyncSession):
    await upsert_builtin_rule(db_session, builtin_data())
    await upsert_builtin_rule(db_session, builtin_data(name="Secrets Detection v2", action="warn"))

    from sqlalchemy import select
    result = await db_session.execute(select(Rule).where(Rule.id == "builtin-secrets-v1"))
    rule = result.scalar_one_or_none()
    assert rule is not None
    assert rule.name == "Secrets Detection v2"
    assert rule.action == "warn"


@pytest.mark.asyncio
async def test_upsert_builtin_rule_does_not_overwrite_custom(db_session: AsyncSession):
    """If a rule with the same id exists but source=custom, upsert should not change it."""
    # Create a custom rule with the same id
    custom_body = make_rule_create(id="builtin-secrets-v1", name="My Custom Rule")
    await create_rule(db_session, custom_body)

    # Attempt to upsert a builtin with the same id
    await upsert_builtin_rule(db_session, builtin_data(name="Should Not Override"))

    from sqlalchemy import select
    result = await db_session.execute(select(Rule).where(Rule.id == "builtin-secrets-v1"))
    rule = result.scalar_one_or_none()
    assert rule is not None
    assert rule.name == "My Custom Rule"
    assert rule.source == "custom"
