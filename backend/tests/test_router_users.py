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


TEST_ADMIN_ID = uuid.uuid4()
TEST_ADMIN_EMAIL = "admin@test.local"

TEST_EDITOR_ID = uuid.uuid4()
TEST_EDITOR_EMAIL = "editor@test.local"

TEST_VIEWER_ID = uuid.uuid4()
TEST_VIEWER_EMAIL = "viewer@test.local"


@pytest_asyncio.fixture
async def db_with_users():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        admin = User(
            id=TEST_ADMIN_ID,
            email=TEST_ADMIN_EMAIL,
            name="Admin User",
            role="admin",
            active=True,
        )
        editor = User(
            id=TEST_EDITOR_ID,
            email=TEST_EDITOR_EMAIL,
            name="Editor User",
            role="editor",
            active=True,
        )
        viewer = User(
            id=TEST_VIEWER_ID,
            email=TEST_VIEWER_EMAIL,
            name="Viewer User",
            role="viewer",
            active=True,
        )
        session.add_all([admin, editor, viewer])
        await session.commit()

    async def override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override
    yield session_factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def admin_client(db_with_users):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie(str(TEST_ADMIN_ID), "admin", TEST_ADMIN_EMAIL)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest_asyncio.fixture
async def editor_client(db_with_users):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie(str(TEST_EDITOR_ID), "editor", TEST_EDITOR_EMAIL)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest_asyncio.fixture
async def viewer_client(db_with_users):
    transport = ASGITransport(app=app)
    cookie = create_signed_cookie(str(TEST_VIEWER_ID), "viewer", TEST_VIEWER_EMAIL)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={COOKIE_NAME: cookie},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_list_users_admin(admin_client: AsyncClient):
    resp = await admin_client.get("/api/v1/users")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    emails = [u["email"] for u in data]
    assert TEST_ADMIN_EMAIL in emails


@pytest.mark.asyncio
async def test_list_users_editor(editor_client: AsyncClient):
    resp = await editor_client.get("/api/v1/users")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_users_viewer_returns_403(viewer_client: AsyncClient):
    resp = await viewer_client.get("/api/v1/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
@patch("app.routers.users.send_invite_email", new_callable=AsyncMock)
async def test_invite_user_admin(mock_send, admin_client: AsyncClient):
    resp = await admin_client.post(
        "/api/v1/users/invite",
        json={"email": "newuser@test.local", "name": "New User", "role": "viewer"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "newuser@test.local"
    assert data["active"] is False
    assert data["role"] == "viewer"
    mock_send.assert_awaited_once()


@pytest.mark.asyncio
@patch("app.routers.users.send_invite_email", new_callable=AsyncMock)
async def test_invite_duplicate_email_returns_409(mock_send, admin_client: AsyncClient):
    # First invite
    resp = await admin_client.post(
        "/api/v1/users/invite",
        json={"email": "dup@test.local", "name": "Dup User", "role": "viewer"},
    )
    assert resp.status_code == 201

    # Second invite with same email
    resp = await admin_client.post(
        "/api/v1/users/invite",
        json={"email": "dup@test.local", "name": "Dup User 2", "role": "viewer"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
@patch("app.routers.users.send_invite_email", new_callable=AsyncMock)
async def test_invite_existing_user_returns_409(mock_send, admin_client: AsyncClient):
    # Existing user from fixture
    resp = await admin_client.post(
        "/api/v1/users/invite",
        json={"email": TEST_VIEWER_EMAIL, "name": "Viewer Again", "role": "viewer"},
    )
    assert resp.status_code == 409
    mock_send.assert_not_awaited()


@pytest.mark.asyncio
async def test_invite_user_editor_returns_403(editor_client: AsyncClient):
    resp = await editor_client.post(
        "/api/v1/users/invite",
        json={"email": "another@test.local", "name": "Another", "role": "viewer"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_user_role_admin(admin_client: AsyncClient):
    resp = await admin_client.put(
        f"/api/v1/users/{TEST_VIEWER_ID}",
        json={"role": "editor"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "editor"
    assert data["id"] == str(TEST_VIEWER_ID)


@pytest.mark.asyncio
async def test_update_user_not_found(admin_client: AsyncClient):
    missing_id = uuid.uuid4()
    resp = await admin_client.put(
        f"/api/v1/users/{missing_id}",
        json={"role": "viewer"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_deactivate_user_admin(admin_client: AsyncClient):
    resp = await admin_client.delete(f"/api/v1/users/{TEST_VIEWER_ID}")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_deactivate_user_not_found(admin_client: AsyncClient):
    missing_id = uuid.uuid4()
    resp = await admin_client.delete(f"/api/v1/users/{missing_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_editor_can_list_users_but_not_invite(editor_client: AsyncClient):
    # Editor can list
    list_resp = await editor_client.get("/api/v1/users")
    assert list_resp.status_code == 200

    # Editor cannot invite
    invite_resp = await editor_client.post(
        "/api/v1/users/invite",
        json={"email": "tryinvite@test.local", "name": "Try", "role": "viewer"},
    )
    assert invite_resp.status_code == 403
