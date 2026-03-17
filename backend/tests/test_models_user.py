import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.models import Base
import app.models.user  # noqa: F401
import app.models.otp_code  # noqa: F401
from app.models.user import User
from app.models.otp_code import OtpCode


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
async def test_create_user_all_fields(db_session: AsyncSession):
    user_id = uuid.uuid4()
    inviter_id = uuid.uuid4()

    inviter = User(
        id=inviter_id,
        email="inviter@example.com",
        name="Inviter User",
        role="admin",
        active=True,
    )
    db_session.add(inviter)
    await db_session.commit()

    user = User(
        id=user_id,
        email="user@example.com",
        name="Test User",
        role="editor",
        active=True,
        invited_by=inviter_id,
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.get(User, user_id)
    assert result is not None
    assert result.email == "user@example.com"
    assert result.name == "Test User"
    assert result.role == "editor"
    assert result.active is True
    assert result.invited_by == inviter_id
    assert result.created_at is not None


@pytest.mark.asyncio
async def test_user_defaults(db_session: AsyncSession):
    user = User(
        email="defaults@example.com",
        name="Default User",
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.get(User, user.id)
    assert result is not None
    assert result.role == "viewer"
    assert result.active is False
    assert result.invited_by is None
    assert result.created_at is not None


@pytest.mark.asyncio
async def test_create_otp_code_linked_to_user(db_session: AsyncSession):
    user = User(
        email="otp@example.com",
        name="OTP User",
    )
    db_session.add(user)
    await db_session.commit()

    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    otp = OtpCode(
        user_id=user.id,
        code="123456",
        expires_at=expires,
    )
    db_session.add(otp)
    await db_session.commit()

    result = await db_session.get(OtpCode, otp.id)
    assert result is not None
    assert result.user_id == user.id
    assert result.code == "123456"
    assert result.used is False
    assert result.expires_at is not None
