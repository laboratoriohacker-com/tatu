import pytest
import pytest_asyncio
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.models import Base
from app.models.user import User
from app.models.otp_code import OtpCode
from app.services.user_service import (
    create_user,
    get_user_by_email,
    list_users,
    bootstrap_admin,
    update_user,
    activate_user,
)
from app.services.otp_service import create_otp, verify_otp
from app.schemas.user import UserUpdate


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
async def test_create_user(db_session: AsyncSession):
    user = await create_user(db_session, email="alice@tatu.local", name="Alice", role="editor")
    assert user.id is not None
    assert user.email == "alice@tatu.local"
    assert user.name == "Alice"
    assert user.role == "editor"
    assert user.active is False
    assert user.invited_by is None


@pytest.mark.asyncio
async def test_get_user_by_email_found(db_session: AsyncSession):
    await create_user(db_session, email="bob@tatu.local", name="Bob")
    found = await get_user_by_email(db_session, "bob@tatu.local")
    assert found is not None
    assert found.name == "Bob"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(db_session: AsyncSession):
    result = await get_user_by_email(db_session, "nobody@tatu.local")
    assert result is None


@pytest.mark.asyncio
async def test_list_users(db_session: AsyncSession):
    await create_user(db_session, email="user1@tatu.local", name="User One")
    await create_user(db_session, email="user2@tatu.local", name="User Two")
    users = await list_users(db_session)
    assert len(users) == 2
    emails = {u.email for u in users}
    assert "user1@tatu.local" in emails
    assert "user2@tatu.local" in emails


@pytest.mark.asyncio
async def test_bootstrap_admin_creates_on_empty_db(db_session: AsyncSession):
    admin = await bootstrap_admin(db_session, "admin@tatu.local")
    assert admin is not None
    assert admin.email == "admin@tatu.local"
    assert admin.role == "admin"
    assert admin.active is True


@pytest.mark.asyncio
async def test_bootstrap_admin_returns_none_when_users_exist(db_session: AsyncSession):
    await create_user(db_session, email="existing@tatu.local", name="Existing")
    result = await bootstrap_admin(db_session, "admin@tatu.local")
    assert result is None


@pytest.mark.asyncio
async def test_create_otp_and_verify_correct_code(db_session: AsyncSession):
    user = await create_user(db_session, email="otp_user@tatu.local", name="OTP User", active=True)
    code = await create_otp(db_session, user.id)
    assert len(code) == 6
    assert code.isdigit()
    result = await verify_otp(db_session, user.id, code)
    assert result is True


@pytest.mark.asyncio
async def test_verify_otp_marks_code_as_used(db_session: AsyncSession):
    user = await create_user(db_session, email="otp_used@tatu.local", name="OTP Used", active=True)
    code = await create_otp(db_session, user.id)
    # First verify succeeds
    first = await verify_otp(db_session, user.id, code)
    assert first is True
    # Second verify fails (already used)
    second = await verify_otp(db_session, user.id, code)
    assert second is False


@pytest.mark.asyncio
async def test_verify_otp_wrong_code_returns_false(db_session: AsyncSession):
    user = await create_user(db_session, email="otp_wrong@tatu.local", name="OTP Wrong", active=True)
    await create_otp(db_session, user.id)
    result = await verify_otp(db_session, user.id, "000000")
    assert result is False


@pytest.mark.asyncio
async def test_update_user_role(db_session: AsyncSession):
    user = await create_user(db_session, email="role_change@tatu.local", name="Role Change", role="viewer")
    assert user.role == "viewer"
    updated = await update_user(db_session, user.id, UserUpdate(role="admin"))
    assert updated is not None
    assert updated.role == "admin"


@pytest.mark.asyncio
async def test_activate_user(db_session: AsyncSession):
    user = await create_user(db_session, email="inactive@tatu.local", name="Inactive", active=False)
    assert user.active is False
    activated = await activate_user(db_session, user.id)
    assert activated is not None
    assert activated.active is True
