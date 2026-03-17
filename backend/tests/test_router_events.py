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
