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
            compliance_mappings=["SOC2 CC6.1", "LGPD Art. 46", "ISO 27001 A.9.4"],
        ))
        session.add(Rule(
            id="destructive-cmd-blocker",
            name="Destructive Cmd Blocker",
            format="yaml",
            content="---",
            source="builtin",
            category="destructive",
            severity="high",
            mode="strict",
            action="block",
            hook_event="PreToolUse",
            matcher="Bash",
            enabled=True,
            compliance_mappings=["CPS234 Logging", "ISO 27001 A.12.4"],
        ))

        for i in range(20):
            session.add(Event(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i * 2),
                hook_name="Secrets Leak Prevention" if i % 2 == 0 else "Destructive Cmd Blocker",
                hook_event="PreToolUse",
                severity="critical" if i < 5 else "info",
                status="blocked" if i < 8 else "allowed",
                message=f"Event {i}",
                developer=f"dev{i % 3}",
                repository="test-repo",
                session_id=f"sess-{i % 4}",
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
async def test_top_rules_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/overview/top-rules")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert all("triggers" in h and "blocks" in h and "block_rate" in h for h in data)


@pytest.mark.asyncio
async def test_compliance_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/compliance")
    assert resp.status_code == 200
    data = resp.json()
    assert "frameworks" in data
    assert "mappings" in data
    assert len(data["frameworks"]) == 9


@pytest.mark.asyncio
async def test_developers_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/developers")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    assert all("name" in d and "sessions" in d and "blocks" in d and "risk" in d for d in data)


@pytest.mark.asyncio
async def test_audit_endpoint(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 20
    assert len(data["items"]) == 20


@pytest.mark.asyncio
async def test_audit_csv_export(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/audit?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.strip().split("\n")
    assert len(lines) == 21  # header + 20 rows
