import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.event import Event
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
        for i in range(60):
            session.add(Event(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i),
                hook_name="Secrets Leak Prevention" if i % 2 == 0 else "Cmd Blocker",
                hook_event="PreToolUse",
                severity="critical" if i % 3 == 0 else "warning",
                status="blocked" if i % 2 == 0 else "allowed",
                message=f"Test event {i}",
                developer=f"dev{i % 3}",
                repository="test-repo",
                session_id=f"sess-{i}",
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
    async with AsyncClient(transport=transport, base_url="http://test", cookies={COOKIE_NAME: cookie}) as c:
        yield c


@pytest.mark.asyncio
async def test_alerts_default_pagination(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["per_page"] == 50
    assert data["page"] == 1
    assert data["total"] == 60
    assert data["pages"] == 2
    assert len(data["items"]) == 50


@pytest.mark.asyncio
async def test_alerts_page_2(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?page=2")
    data = resp.json()
    assert len(data["items"]) == 10


@pytest.mark.asyncio
async def test_alerts_filter_severity(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?severity=critical")
    data = resp.json()
    assert all(item["severity"] == "critical" for item in data["items"])


@pytest.mark.asyncio
async def test_alerts_filter_hook(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/alerts?hook=Cmd+Blocker")
    data = resp.json()
    assert all(item["hook_name"] == "Cmd Blocker" for item in data["items"])
