import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.models import Base
from app.models.rule import Rule
from app.models.rule_version import RuleVersion


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
async def test_create_rule(db_session: AsyncSession):
    rule = Rule(
        id="secrets-leak-prevention-v1",
        name="Secrets Leak Prevention",
        format="yaml",
        content="rules:\n  - id: secrets-leak\n    pattern: AWS_SECRET",
        source="builtin",
        enabled=True,
        category="offensive_guardrails",
        severity="critical",
        mode="strict",
        action="block",
        hook_event="PreToolUse",
        matcher="Bash|Write|Edit",
        version_added=1,
    )
    db_session.add(rule)
    await db_session.commit()

    result = await db_session.get(Rule, "secrets-leak-prevention-v1")
    assert result is not None
    assert result.name == "Secrets Leak Prevention"
    assert result.format == "yaml"
    assert result.source == "builtin"
    assert result.enabled is True
    assert result.category == "offensive_guardrails"
    assert result.severity == "critical"
    assert result.mode == "strict"
    assert result.action == "block"
    assert result.hook_event == "PreToolUse"
    assert result.matcher == "Bash|Write|Edit"
    assert result.version_added == 1


@pytest.mark.asyncio
async def test_create_rule_defaults(db_session: AsyncSession):
    rule = Rule(
        id="pii-detector-v1",
        name="PII Detector",
        format="yara",
        content="rule PII { strings: $cpf = /\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}/ condition: $cpf }",
        source="custom",
        category="compliance",
        severity="high",
        action="warn",
        hook_event="PreToolUse",
        matcher="Write|Edit",
    )
    db_session.add(rule)
    await db_session.commit()

    result = await db_session.get(Rule, "pii-detector-v1")
    assert result is not None
    assert result.enabled is True        # default
    assert result.mode == "audit"        # default
    assert result.version_added == 1     # default


@pytest.mark.asyncio
async def test_create_rule_version(db_session: AsyncSession):
    rv = RuleVersion(id=1, version=3)
    db_session.add(rv)
    await db_session.commit()

    result = await db_session.get(RuleVersion, 1)
    assert result is not None
    assert result.version == 3


@pytest.mark.asyncio
async def test_create_rule_version_defaults(db_session: AsyncSession):
    rv = RuleVersion(id=2)
    db_session.add(rv)
    await db_session.commit()

    result = await db_session.get(RuleVersion, 2)
    assert result is not None
    assert result.version == 1           # default


@pytest.mark.asyncio
async def test_multiple_rules(db_session: AsyncSession):
    rules = [
        Rule(
            id=f"rule-{i}",
            name=f"Rule {i}",
            format="yaml",
            content=f"content {i}",
            source="builtin",
            category="security",
            severity="medium",
            action="log",
            hook_event="PostToolUse",
            matcher="*",
        )
        for i in range(3)
    ]
    for rule in rules:
        db_session.add(rule)
    await db_session.commit()

    for i in range(3):
        result = await db_session.get(Rule, f"rule-{i}")
        assert result is not None
        assert result.name == f"Rule {i}"
