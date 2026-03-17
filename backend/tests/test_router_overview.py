import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.event import Event
from app.models.rule import Rule
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
        # Add a secrets rule so stats_service can find it
        session.add(Rule(
            id="secrets-leak-prevention",
            name="Secrets Leak Prevention",
            format="yaml",
            content="---",
            source="builtin",
            category="secrets",
            severity="critical",
            mode="strict",
            action="block",
            hook_event="PreToolUse",
            matcher="Bash|Write|Edit",
            enabled=True,
            compliance_mappings=[],
        ))

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
    cookie = create_signed_cookie("test-user-id", "admin", "test@tatu.local")
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
