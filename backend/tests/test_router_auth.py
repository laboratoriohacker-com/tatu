import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models import Base
from app.models.user import User
from app.database import get_db
from app.auth import create_signed_cookie, COOKIE_NAME
from app.services.otp_service import create_otp


TEST_USER_ID = uuid.uuid4()
TEST_EMAIL = "admin@tatu.local"


@pytest_asyncio.fixture
async def db_with_user():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        user = User(
            id=TEST_USER_ID,
            email=TEST_EMAIL,
            name="Admin",
            role="admin",
            active=True,
        )
        session.add(user)
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield session_factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_with_user):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def authed_client(db_with_user):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie(str(TEST_USER_ID), "admin", TEST_EMAIL)
    async with AsyncClient(
        transport=transport, base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest.mark.asyncio
@patch("app.routers.auth.send_otp_email", new_callable=AsyncMock)
async def test_login_sends_otp(mock_send, client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={"email": TEST_EMAIL})
    assert resp.status_code == 200
    assert resp.json()["message"] == "otp_sent"
    mock_send.assert_awaited_once()


@pytest.mark.asyncio
@patch("app.routers.auth.send_otp_email", new_callable=AsyncMock)
async def test_login_invalid_email(mock_send, client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={"email": "nobody@tatu.local"})
    assert resp.status_code == 401
    mock_send.assert_not_awaited()


@pytest.mark.asyncio
@patch("app.routers.auth.send_otp_email", new_callable=AsyncMock)
async def test_verify_otp_success(mock_send, client: AsyncClient, db_with_user):
    # First trigger login to create OTP
    await client.post("/api/v1/auth/login", json={"email": TEST_EMAIL})

    # Retrieve the OTP code from the DB
    async with db_with_user() as session:
        from sqlalchemy import select
        from app.models.otp_code import OtpCode
        result = await session.execute(
            select(OtpCode).where(OtpCode.user_id == TEST_USER_ID, OtpCode.used == False)
        )
        otp = result.scalar_one()
        code = otp.code

    resp = await client.post("/api/v1/auth/verify-otp", json={"email": TEST_EMAIL, "code": code})
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == str(TEST_USER_ID)
    assert data["role"] == "admin"
    assert "tatu_session" in resp.cookies


@pytest.mark.asyncio
async def test_verify_otp_wrong_code(client: AsyncClient):
    resp = await client.post("/api/v1/auth/verify-otp", json={"email": TEST_EMAIL, "code": "000000"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_authenticated(authed_client: AsyncClient):
    resp = await authed_client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == TEST_EMAIL
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_me_unauthenticated(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_accept_invite(client: AsyncClient, db_with_user):
    # Create an inactive user to invite
    invite_user_id = uuid.uuid4()
    async with db_with_user() as session:
        user = User(
            id=invite_user_id,
            email="invited@tatu.local",
            name="Invited",
            role="viewer",
            active=False,
        )
        session.add(user)
        await session.commit()

    from app.auth import create_invite_token
    token = create_invite_token(str(invite_user_id))

    resp = await client.get(f"/api/v1/auth/accept-invite?token={token}")
    assert resp.status_code == 200
    assert resp.json()["email"] == "invited@tatu.local"


@pytest.mark.asyncio
async def test_accept_invite_bad_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/accept-invite?token=bad_token")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_api_key_lifecycle(authed_client: AsyncClient):
    create_resp = await authed_client.post(
        "/api/v1/auth/api-keys",
        json={"label": "test-key"},
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    assert data["label"] == "test-key"
    assert data["api_key"].startswith("tatu_")
    key_id = data["id"]

    list_resp = await authed_client.get("/api/v1/auth/api-keys")
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert len(keys) == 1
    assert "api_key" not in keys[0]

    del_resp = await authed_client.delete(f"/api/v1/auth/api-keys/{key_id}")
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_api_key_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/auth/api-keys", json={"label": "test"})
    assert resp.status_code == 401
