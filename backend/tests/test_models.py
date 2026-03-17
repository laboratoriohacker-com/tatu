import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from datetime import datetime, timezone
import uuid

from app.models import Base
from app.models.event import Event

from app.models.api_key import ApiKey


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
async def test_create_event(db_session: AsyncSession):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name="Secrets Leak Prevention",
        hook_event="PreToolUse",
        severity="critical",
        status="blocked",
        message="AWS key detected in config.py",
        developer="carlos.m",
        repository="payments-api",
        session_id="sess-123",
        tool_name="Write",
        metadata_={"file_path": "config.py"},
    )
    db_session.add(event)
    await db_session.commit()
    result = await db_session.get(Event, event.id)
    assert result is not None
    assert result.hook_name == "Secrets Leak Prevention"
    assert result.severity == "critical"
    assert result.tool_name == "Write"
    assert result.metadata_ == {"file_path": "config.py"}


@pytest.mark.asyncio
async def test_create_event_nullable_tool_name(db_session: AsyncSession):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name="Env Hardening",
        hook_event="SessionStart",
        severity="info",
        status="allowed",
        message="Environment validated",
        developer="julio.df",
        repository="pentest-tools",
        session_id="sess-456",
        tool_name=None,
        metadata_={},
    )
    db_session.add(event)
    await db_session.commit()
    result = await db_session.get(Event, event.id)
    assert result.tool_name is None



@pytest.mark.asyncio
async def test_create_api_key(db_session: AsyncSession):
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash="hashed_value_here",
        label="production-hooks",
        created_at=datetime.now(timezone.utc),
        active=True,
    )
    db_session.add(api_key)
    await db_session.commit()
    result = await db_session.get(ApiKey, api_key.id)
    assert result.label == "production-hooks"
    assert result.active is True
    assert result.last_used_at is None
