"""
Tests that the app loads built-in rules from the rules/ directory on startup.

Uses an in-memory SQLite DB (same pattern as test_router_rules.py), but also
manually triggers the rule-loading code so the DB is pre-populated with
built-in rules — mimicking what the lifespan function does on a real startup.
"""

import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME
from app.services.rule_loader import load_rules_from_directory
from app.services.rule_service import upsert_builtin_rule


RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "rules")


@pytest_asyncio.fixture
async def db_with_builtin_rules():
    """In-memory DB pre-populated with the built-in rules from the rules/ dir."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Load built-in rules exactly as the lifespan function does
    if os.path.isdir(RULES_DIR):
        rule_defs = load_rules_from_directory(RULES_DIR)
        async with session_factory() as db:
            for rule_data in rule_defs:
                await upsert_builtin_rule(db, rule_data)
            await db.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def authed_client(db_with_builtin_rules):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie("test-user-id", "admin", "test@tatu.local")
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_builtin_rules_loaded_on_startup(authed_client: AsyncClient):
    """Rules endpoint returns built-in rules after startup rule loading."""
    resp = await authed_client.get("/api/v1/rules?source=builtin")
    assert resp.status_code == 200
    rules = resp.json()

    # At least one built-in rule must exist
    assert len(rules) >= 1, "Expected at least 1 built-in rule, got 0"

    # All returned rules must have source=builtin
    for rule in rules:
        assert rule["source"] == "builtin", (
            f"Rule {rule['id']} has source={rule['source']!r}, expected 'builtin'"
        )


@pytest.mark.asyncio
async def test_aws_access_key_rule_exists(authed_client: AsyncClient):
    """The aws-access-key rule from rules/secrets/ must be present."""
    resp = await authed_client.get("/api/v1/rules?source=builtin")
    assert resp.status_code == 200
    rule_ids = {r["id"] for r in resp.json()}
    assert "aws-access-key" in rule_ids, (
        f"Expected 'aws-access-key' rule to be loaded. Found: {rule_ids}"
    )


@pytest.mark.asyncio
async def test_builtin_rules_are_enabled(authed_client: AsyncClient):
    """All built-in rules should be enabled by default."""
    resp = await authed_client.get("/api/v1/rules?source=builtin")
    assert resp.status_code == 200
    for rule in resp.json():
        assert rule["enabled"] is True, (
            f"Rule {rule['id']} should be enabled but enabled={rule['enabled']}"
        )
