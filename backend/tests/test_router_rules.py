import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME


@pytest_asyncio.fixture
async def empty_db():
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
async def authed_client(empty_db):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie("test-user-id", "admin", "test@tatu.local")
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest_asyncio.fixture
async def anon_client(empty_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


RULE_PAYLOAD = {
    "id": "test-rule-001",
    "name": "Test Secrets Rule",
    "format": "yaml",
    "content": "pattern: password",
    "category": "secrets",
    "severity": "critical",
    "mode": "strict",
    "action": "block",
    "hook_event": "PreToolUse",
    "matcher": "Bash|Write",
}


@pytest.mark.asyncio
async def test_create_rule(authed_client: AsyncClient):
    resp = await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)
    assert resp.status_code == 201
    data = resp.json()
    assert data["id"] == "test-rule-001"
    assert data["source"] == "custom"
    assert data["name"] == "Test Secrets Rule"
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_list_rules(authed_client: AsyncClient):
    # Create a rule first
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    resp = await authed_client.get("/api/v1/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["id"] == "test-rule-001"


@pytest.mark.asyncio
async def test_list_rules_filter_category(authed_client: AsyncClient):
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    # Filter by matching category
    resp = await authed_client.get("/api/v1/rules?category=secrets")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # Filter by non-matching category
    resp = await authed_client.get("/api/v1/rules?category=pii")
    assert resp.status_code == 200
    assert len(resp.json()) == 0


@pytest.mark.asyncio
async def test_update_rule(authed_client: AsyncClient):
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    resp = await authed_client.put(
        "/api/v1/rules/test-rule-001",
        json={"name": "Updated Name", "mode": "audit"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Updated Name"
    assert data["mode"] == "audit"
    # unchanged fields should remain
    assert data["action"] == "block"


@pytest.mark.asyncio
async def test_update_rule_not_found(authed_client: AsyncClient):
    resp = await authed_client.put(
        "/api/v1/rules/nonexistent-id",
        json={"name": "Does not matter"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_rule(authed_client: AsyncClient):
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    resp = await authed_client.delete("/api/v1/rules/test-rule-001")
    assert resp.status_code == 204

    # Rule still exists but is disabled
    list_resp = await authed_client.get("/api/v1/rules")
    assert list_resp.status_code == 200
    rules = list_resp.json()
    assert len(rules) == 1
    assert rules[0]["enabled"] is False


@pytest.mark.asyncio
async def test_delete_rule_not_found(authed_client: AsyncClient):
    resp = await authed_client.delete("/api/v1/rules/nonexistent-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sync_with_version_zero_returns_rules(authed_client: AsyncClient):
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    resp = await authed_client.get("/api/v1/rules/sync?version=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "version" in data
    assert "rules" in data
    assert len(data["rules"]) == 1
    assert data["rules"][0]["id"] == "test-rule-001"


@pytest.mark.asyncio
async def test_sync_up_to_date(authed_client: AsyncClient):
    await authed_client.post("/api/v1/rules", json=RULE_PAYLOAD)

    # Get current version
    sync_resp = await authed_client.get("/api/v1/rules/sync?version=0")
    current_version = sync_resp.json()["version"]

    # Request with current version — should get up_to_date
    resp = await authed_client.get(f"/api/v1/rules/sync?version={current_version}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "up_to_date"
    assert data["version"] == current_version


@pytest.mark.asyncio
async def test_sync_no_auth_required(anon_client: AsyncClient):
    """Sync endpoint must be accessible without authentication."""
    resp = await anon_client.get("/api/v1/rules/sync?version=0")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_create_rule_without_auth_returns_401(anon_client: AsyncClient):
    resp = await anon_client.post("/api/v1/rules", json=RULE_PAYLOAD)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_rules_without_auth_returns_401(anon_client: AsyncClient):
    resp = await anon_client.get("/api/v1/rules")
    assert resp.status_code == 401
