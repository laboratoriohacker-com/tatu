# OTP Auth & User Management Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace shared-password auth with per-user email OTP login, add User model with admin/editor/viewer roles, and build a Users management UI in Settings.

**Architecture:** User and OtpCode models in the backend, email service via aiosmtplib, modified auth flow (email → OTP → session cookie with user_id/role), role-based access control via `require_role()` dependency, frontend two-step login form, and Users section in Settings page.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0, aiosmtplib, itsdangerous, Mailpit (dev), React 18, TypeScript.

**Spec:** `docs/superpowers/specs/2026-03-14-otp-auth-users-design.md`

---

## Chunk 1: Backend Models, Config & Email Service

### Task 1: Update config with SMTP and admin email settings

**Files:**
- Modify: `backend/app/config.py`
- Modify: `backend/requirements.txt`

- [ ] **Step 1: Add aiosmtplib to requirements.txt**

Add `aiosmtplib==3.*` to `backend/requirements.txt`.

- [ ] **Step 2: Update Settings class in config.py**

Replace `dashboard_password: str` with the new fields:

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "TATU_"}

    database_url: str = "sqlite+aiosqlite:///./tatu.db"
    secret_key: str
    cors_origins: list[str] = ["http://localhost:5173"]
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # Admin bootstrap
    admin_email: str = ""

    # SMTP
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    smtp_from: str = "noreply@tatu.local"


settings = Settings()
```

- [ ] **Step 3: Update test_config.py**

The existing test sets `TATU_DASHBOARD_PASSWORD` — update to remove it and ensure the new defaults work:

```python
def test_settings_loads_defaults():
    os.environ.setdefault("TATU_SECRET_KEY", "testsecret")
    from app.config import settings
    assert settings.database_url == "sqlite+aiosqlite:///./tatu.db"
    assert settings.cors_origins == ["http://localhost:5173"]
    assert settings.smtp_host == "localhost"
    assert settings.smtp_port == 1025
    assert settings.admin_email == ""
```

- [ ] **Step 4: Update docker-compose.yml environment**

Remove `TATU_DASHBOARD_PASSWORD` from the `backend` service environment. Add `TATU_ADMIN_EMAIL`. Also remove it from the `test` service and add `TATU_ADMIN_EMAIL=test@tatu.local`.

Update the test service:
```yaml
  test:
    environment:
      - TATU_SECRET_KEY=testsecret
      - TATU_DATABASE_URL=sqlite+aiosqlite:///./test.db
      - TATU_ADMIN_EMAIL=test@tatu.local
```

- [ ] **Step 5: Add Mailpit service to docker-compose.yml**

```yaml
  mailpit:
    image: axllent/mailpit
    ports:
      - "1025:1025"
      - "8025:8025"
```

- [ ] **Step 6: Run tests to verify config changes don't break**

```bash
docker compose --profile test run --rm test -v
```

Note: Some auth tests will fail because `dashboard_password` is removed. That's expected — we'll fix them in later tasks.

- [ ] **Step 7: Commit**

```bash
git add backend/app/config.py backend/requirements.txt docker-compose.yml
git commit -m "feat: update config for OTP auth (SMTP settings, admin email, remove shared password)"
```

---

### Task 2: User and OtpCode models

**Files:**
- Create: `backend/app/models/user.py`
- Create: `backend/app/models/otp_code.py`
- Modify: `backend/app/main.py` (register models)

- [ ] **Step 1: Write User model**

```python
# backend/app/models/user.py
import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin | editor | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, default=None
    )
```

- [ ] **Step 2: Write OtpCode model**

```python
# backend/app/models/otp_code.py
import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class OtpCode(Base):
    __tablename__ = "otp_codes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    code: Mapped[str] = mapped_column(String(6))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
```

- [ ] **Step 3: Register models in main.py**

Add alongside existing model imports:

```python
import app.models.user  # noqa: F401
import app.models.otp_code  # noqa: F401
```

- [ ] **Step 4: Write model tests**

```python
# backend/tests/test_models_user.py
import uuid
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models import Base
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
async def test_create_user(db_session):
    user = User(
        id=uuid.uuid4(),
        email="admin@tatu.local",
        name="Admin",
        role="admin",
        active=True,
    )
    db_session.add(user)
    await db_session.commit()
    result = await db_session.get(User, user.id)
    assert result.email == "admin@tatu.local"
    assert result.role == "admin"
    assert result.active is True


@pytest.mark.asyncio
async def test_create_otp_code(db_session):
    user = User(id=uuid.uuid4(), email="test@tatu.local", name="Test", role="viewer", active=True)
    db_session.add(user)
    await db_session.commit()

    otp = OtpCode(
        id=uuid.uuid4(),
        user_id=user.id,
        code="123456",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db_session.add(otp)
    await db_session.commit()
    result = await db_session.get(OtpCode, otp.id)
    assert result.code == "123456"
    assert result.used is False


@pytest.mark.asyncio
async def test_user_defaults(db_session):
    user = User(id=uuid.uuid4(), email="default@tatu.local", name="Default")
    db_session.add(user)
    await db_session.commit()
    result = await db_session.get(User, user.id)
    assert result.role == "viewer"
    assert result.active is False
    assert result.invited_by is None
```

- [ ] **Step 5: Run tests**

```bash
docker compose --profile test run --rm test tests/test_models_user.py -v
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/models/user.py backend/app/models/otp_code.py backend/app/main.py backend/tests/test_models_user.py
git commit -m "feat: add User and OtpCode models"
```

---

### Task 3: User and auth schemas

**Files:**
- Create: `backend/app/schemas/user.py`
- Modify: `backend/app/schemas/auth.py`

- [ ] **Step 1: Create user schemas**

```python
# backend/app/schemas/user.py
from datetime import datetime
from uuid import UUID
from typing import Literal

from pydantic import BaseModel, EmailStr


class UserInvite(BaseModel):
    email: str
    name: str
    role: Literal["admin", "editor", "viewer"] = "viewer"


class UserUpdate(BaseModel):
    role: Literal["admin", "editor", "viewer"] | None = None
    active: bool | None = None


class UserResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    email: str
    name: str
    role: str
    active: bool
    created_at: datetime
    invited_by: UUID | None
```

- [ ] **Step 2: Update auth schemas**

Replace the existing `backend/app/schemas/auth.py`:

```python
# backend/app/schemas/auth.py
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str


class LoginResponse(BaseModel):
    message: str = "otp_sent"


class OtpVerifyRequest(BaseModel):
    email: str
    code: str


class OtpVerifyResponse(BaseModel):
    message: str = "authenticated"
    user_id: str
    role: str


class ApiKeyCreate(BaseModel):
    label: str


class ApiKeyCreateResponse(BaseModel):
    id: UUID
    label: str
    api_key: str


class ApiKeyResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    label: str
    created_at: datetime
    last_used_at: datetime | None
    active: bool
```

- [ ] **Step 3: Write schema tests**

```python
# backend/tests/test_schemas_user.py
import pytest
from pydantic import ValidationError


def test_user_invite_valid():
    from app.schemas.user import UserInvite
    invite = UserInvite(email="new@tatu.local", name="New User", role="editor")
    assert invite.role == "editor"


def test_user_invite_default_role():
    from app.schemas.user import UserInvite
    invite = UserInvite(email="new@tatu.local", name="New User")
    assert invite.role == "viewer"


def test_user_invite_invalid_role():
    from app.schemas.user import UserInvite
    with pytest.raises(ValidationError):
        UserInvite(email="new@tatu.local", name="New User", role="superadmin")


def test_login_request():
    from app.schemas.auth import LoginRequest
    req = LoginRequest(email="admin@tatu.local")
    assert req.email == "admin@tatu.local"


def test_otp_verify_request():
    from app.schemas.auth import OtpVerifyRequest
    req = OtpVerifyRequest(email="admin@tatu.local", code="123456")
    assert req.code == "123456"
```

- [ ] **Step 4: Run tests**

```bash
docker compose --profile test run --rm test tests/test_schemas_user.py -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas/user.py backend/app/schemas/auth.py backend/tests/test_schemas_user.py
git commit -m "feat: add user schemas and update auth schemas for OTP flow"
```

---

### Task 4: Email service

**Files:**
- Create: `backend/app/services/email_service.py`

- [ ] **Step 1: Write email service**

```python
# backend/app/services/email_service.py
"""Email sending service using aiosmtplib."""
from email.message import EmailMessage

import aiosmtplib

from app.config import settings


async def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    await aiosmtplib.send(
        msg,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user or None,
        password=settings.smtp_password or None,
        use_tls=settings.smtp_use_tls,
    )


async def send_otp_email(to: str, code: str) -> None:
    subject = f"Tatu — Your login code: {code}"
    body = (
        f"Your one-time login code is: {code}\n\n"
        f"This code expires in 5 minutes.\n\n"
        f"If you did not request this code, ignore this email."
    )
    await send_email(to, subject, body)


async def send_invite_email(to: str, invite_url: str, inviter_name: str) -> None:
    subject = "Tatu — You've been invited"
    body = (
        f"You've been invited to join the Tatu DevSecOps platform by {inviter_name}.\n\n"
        f"Click here to accept your invitation:\n{invite_url}\n\n"
        f"This link expires in 24 hours."
    )
    await send_email(to, subject, body)
```

- [ ] **Step 2: Write test (mocking SMTP)**

```python
# backend/tests/test_email_service.py
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_send_otp_email():
    with patch("app.services.email_service.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        from app.services.email_service import send_otp_email
        await send_otp_email("test@tatu.local", "123456")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "123456" in msg.get_content()
        assert msg["To"] == "test@tatu.local"


@pytest.mark.asyncio
async def test_send_invite_email():
    with patch("app.services.email_service.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        from app.services.email_service import send_invite_email
        await send_invite_email("new@tatu.local", "https://tatu.local/accept?token=abc", "Admin")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "accept?token=abc" in msg.get_content()
        assert "Admin" in msg.get_content()
```

- [ ] **Step 3: Run tests**

```bash
docker compose --profile test run --rm test tests/test_email_service.py -v
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/services/email_service.py backend/tests/test_email_service.py
git commit -m "feat: add email service with OTP and invitation sending"
```

---

### Task 5: OTP and user services

**Files:**
- Create: `backend/app/services/otp_service.py`
- Create: `backend/app/services/user_service.py`

- [ ] **Step 1: Write OTP service**

```python
# backend/app/services/otp_service.py
import secrets
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp_code import OtpCode


OTP_EXPIRY_MINUTES = 5


def generate_otp_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


async def create_otp(db: AsyncSession, user_id: uuid.UUID) -> str:
    code = generate_otp_code()
    otp = OtpCode(
        id=uuid.uuid4(),
        user_id=user_id,
        code=code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES),
    )
    db.add(otp)
    await db.commit()
    return code


async def verify_otp(db: AsyncSession, user_id: uuid.UUID, code: str) -> bool:
    result = await db.execute(
        select(OtpCode).where(
            OtpCode.user_id == user_id,
            OtpCode.code == code,
            OtpCode.used == False,  # noqa: E712
            OtpCode.expires_at > datetime.now(timezone.utc),
        )
    )
    otp = result.scalar_one_or_none()
    if not otp:
        return False
    otp.used = True
    await db.commit()
    return True
```

- [ ] **Step 2: Write user service**

```python
# backend/app/services/user_service.py
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.user import UserInvite, UserUpdate


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await db.get(User, user_id)


async def list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


async def create_user(
    db: AsyncSession,
    email: str,
    name: str,
    role: str = "viewer",
    active: bool = False,
    invited_by: uuid.UUID | None = None,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        name=name,
        role=role,
        active=active,
        invited_by=invited_by,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def update_user(db: AsyncSession, user_id: uuid.UUID, body: UserUpdate) -> User | None:
    user = await db.get(User, user_id)
    if not user:
        return None
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    await db.commit()
    await db.refresh(user)
    return user


async def activate_user(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    user = await db.get(User, user_id)
    if not user:
        return None
    user.active = True
    await db.commit()
    await db.refresh(user)
    return user


async def bootstrap_admin(db: AsyncSession, admin_email: str) -> User | None:
    """Create admin user on first startup if no users exist."""
    result = await db.execute(select(User))
    if result.scalar_one_or_none() is not None:
        return None  # users already exist
    return await create_user(db, email=admin_email, name="Admin", role="admin", active=True)
```

- [ ] **Step 3: Write service tests**

```python
# backend/tests/test_user_service.py
import uuid
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models import Base


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
async def test_create_user(db_session):
    from app.services.user_service import create_user
    user = await create_user(db_session, "test@tatu.local", "Test User", role="editor", active=True)
    assert user.email == "test@tatu.local"
    assert user.role == "editor"
    assert user.active is True


@pytest.mark.asyncio
async def test_get_user_by_email(db_session):
    from app.services.user_service import create_user, get_user_by_email
    await create_user(db_session, "find@tatu.local", "Find Me", active=True)
    user = await get_user_by_email(db_session, "find@tatu.local")
    assert user is not None
    assert user.name == "Find Me"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(db_session):
    from app.services.user_service import get_user_by_email
    user = await get_user_by_email(db_session, "nope@tatu.local")
    assert user is None


@pytest.mark.asyncio
async def test_list_users(db_session):
    from app.services.user_service import create_user, list_users
    await create_user(db_session, "a@tatu.local", "A", active=True)
    await create_user(db_session, "b@tatu.local", "B", active=True)
    users = await list_users(db_session)
    assert len(users) == 2


@pytest.mark.asyncio
async def test_bootstrap_admin(db_session):
    from app.services.user_service import bootstrap_admin, list_users
    admin = await bootstrap_admin(db_session, "admin@tatu.local")
    assert admin is not None
    assert admin.role == "admin"
    assert admin.active is True
    # Second call does nothing
    second = await bootstrap_admin(db_session, "admin2@tatu.local")
    assert second is None
    users = await list_users(db_session)
    assert len(users) == 1


@pytest.mark.asyncio
async def test_create_and_verify_otp(db_session):
    from app.services.user_service import create_user
    from app.services.otp_service import create_otp, verify_otp
    user = await create_user(db_session, "otp@tatu.local", "OTP User", active=True)
    code = await create_otp(db_session, user.id)
    assert len(code) == 6
    assert await verify_otp(db_session, user.id, code) is True
    # Cannot reuse
    assert await verify_otp(db_session, user.id, code) is False


@pytest.mark.asyncio
async def test_verify_otp_wrong_code(db_session):
    from app.services.user_service import create_user
    from app.services.otp_service import create_otp, verify_otp
    user = await create_user(db_session, "wrong@tatu.local", "Wrong", active=True)
    await create_otp(db_session, user.id)
    assert await verify_otp(db_session, user.id, "000000") is False


@pytest.mark.asyncio
async def test_update_user_role(db_session):
    from app.services.user_service import create_user, update_user
    from app.schemas.user import UserUpdate
    user = await create_user(db_session, "role@tatu.local", "Role", role="viewer", active=True)
    updated = await update_user(db_session, user.id, UserUpdate(role="editor"))
    assert updated.role == "editor"


@pytest.mark.asyncio
async def test_activate_user(db_session):
    from app.services.user_service import create_user, activate_user
    user = await create_user(db_session, "activate@tatu.local", "Activate")
    assert user.active is False
    activated = await activate_user(db_session, user.id)
    assert activated.active is True
```

- [ ] **Step 4: Run tests**

```bash
docker compose --profile test run --rm test tests/test_user_service.py -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/otp_service.py backend/app/services/user_service.py backend/tests/test_user_service.py
git commit -m "feat: add OTP and user services"
```

---

## Chunk 2: Auth Flow & Role-Based Access

### Task 6: Update auth module with role-based dependencies

**Files:**
- Modify: `backend/app/auth.py`

- [ ] **Step 1: Rewrite auth.py**

Keep API key functions unchanged. Modify cookie functions and add role-based auth:

```python
# backend/app/auth.py
import hashlib
import hmac
import secrets
import time
import uuid

from fastapi import Depends, HTTPException, Request, WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db
from app.models.api_key import ApiKey
from app.models.user import User

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

COOKIE_NAME = "tatu_session"
COOKIE_MAX_AGE = 86400  # 24 hours

_serializer = URLSafeTimedSerializer(settings.secret_key)


# --- API Key functions (unchanged) ---

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def verify_api_key(raw_key: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key), hashed)


def generate_api_key() -> str:
    return f"tatu_{secrets.token_urlsafe(32)}"


async def require_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ApiKey:
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    key_hash = hash_api_key(key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return api_key


# --- Session cookie functions (updated for user data) ---

def create_signed_cookie(user_id: str, role: str, email: str) -> str:
    return _serializer.dumps({
        "user_id": user_id,
        "role": role,
        "email": email,
        "t": int(time.time()),
    })


def decode_signed_cookie(cookie_value: str) -> dict | None:
    try:
        return _serializer.loads(cookie_value, max_age=COOKIE_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


# --- Invite token functions ---

def create_invite_token(user_id: str) -> str:
    return _serializer.dumps({"user_id": user_id, "purpose": "invite"})


def decode_invite_token(token: str) -> dict | None:
    try:
        data = _serializer.loads(token, max_age=86400)  # 24h
        if data.get("purpose") != "invite":
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None


# --- Dashboard auth dependencies ---

async def require_dashboard_auth(request: Request) -> dict:
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    data = decode_signed_cookie(cookie)
    if not data:
        raise HTTPException(status_code=401, detail="Not authenticated")
    request.state.user = data
    return data


def require_role(*roles: str):
    """Factory for role-based access control dependency."""
    async def _check(user_data: dict = Depends(require_dashboard_auth)) -> dict:
        if user_data.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user_data
    return _check


async def require_ws_auth(websocket: WebSocket):
    cookie = websocket.cookies.get(COOKIE_NAME)
    if not cookie:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Not authenticated")
    data = decode_signed_cookie(cookie)
    if not data:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Not authenticated")
```

- [ ] **Step 2: Write auth tests**

Update `backend/tests/test_auth.py` to test the new cookie format and role checking:

```python
# backend/tests/test_auth.py
from app.auth import (
    hash_api_key, verify_api_key,
    create_signed_cookie, decode_signed_cookie,
    create_invite_token, decode_invite_token,
)


def test_hash_and_verify_api_key():
    raw = "tatu_test_key_123"
    hashed = hash_api_key(raw)
    assert verify_api_key(raw, hashed) is True
    assert verify_api_key("wrong", hashed) is False


def test_create_and_decode_signed_cookie():
    cookie = create_signed_cookie("user-id-1", "admin", "admin@tatu.local")
    data = decode_signed_cookie(cookie)
    assert data is not None
    assert data["user_id"] == "user-id-1"
    assert data["role"] == "admin"
    assert data["email"] == "admin@tatu.local"


def test_decode_invalid_cookie():
    data = decode_signed_cookie("invalid-cookie")
    assert data is None


def test_create_and_decode_invite_token():
    token = create_invite_token("user-id-2")
    data = decode_invite_token(token)
    assert data is not None
    assert data["user_id"] == "user-id-2"


def test_decode_invalid_invite_token():
    data = decode_invite_token("bad-token")
    assert data is None
```

- [ ] **Step 3: Run tests**

```bash
docker compose --profile test run --rm test tests/test_auth.py -v
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/auth.py backend/tests/test_auth.py
git commit -m "feat: update auth with user sessions, role-based access, and invite tokens"
```

---

### Task 7: Rewrite auth router for OTP flow

**Files:**
- Modify: `backend/app/routers/auth.py`

- [ ] **Step 1: Rewrite auth router**

```python
# backend/app/routers/auth.py
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    hash_api_key, generate_api_key, create_signed_cookie,
    require_dashboard_auth, require_role,
    create_invite_token, decode_invite_token,
    COOKIE_NAME, COOKIE_MAX_AGE,
)
from app.database import get_db
from app.models.api_key import ApiKey
from app.schemas.auth import (
    LoginRequest, LoginResponse, OtpVerifyRequest, OtpVerifyResponse,
    ApiKeyCreate, ApiKeyCreateResponse, ApiKeyResponse,
)
from app.schemas.user import UserResponse
from app.services.user_service import get_user_by_email, activate_user
from app.services.otp_service import create_otp, verify_otp
from app.services.email_service import send_otp_email

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, body.email)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="Invalid email or account inactive")
    code = await create_otp(db, user.id)
    await send_otp_email(user.email, code)
    return LoginResponse()


@router.post("/verify-otp", response_model=OtpVerifyResponse)
async def verify_otp_endpoint(body: OtpVerifyRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, body.email)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="Invalid email")
    if not await verify_otp(db, user.id, body.code):
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    cookie_value = create_signed_cookie(str(user.id), user.role, user.email)
    response.set_cookie(
        key=COOKIE_NAME,
        value=cookie_value,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return OtpVerifyResponse(user_id=str(user.id), role=user.role)


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    user_data: dict = Depends(require_dashboard_auth),
    db: AsyncSession = Depends(get_db),
):
    from app.services.user_service import get_user_by_id
    user = await get_user_by_id(db, uuid.UUID(user_data["user_id"]))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.get("/accept-invite")
async def accept_invite(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    data = decode_invite_token(token)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid or expired invitation")
    user = await activate_user(db, uuid.UUID(data["user_id"]))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Account activated. You can now log in.", "email": user.email}


# --- API Key endpoints (require editor+ role) ---

@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201,
             dependencies=[Depends(require_role("admin", "editor"))])
async def create_api_key(body: ApiKeyCreate, db: AsyncSession = Depends(get_db)):
    raw_key = generate_api_key()
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash=hash_api_key(raw_key),
        label=body.label,
        created_at=datetime.now(timezone.utc),
        active=True,
    )
    db.add(api_key)
    await db.commit()
    return ApiKeyCreateResponse(id=api_key.id, label=api_key.label, api_key=raw_key)


@router.get("/api-keys", response_model=list[ApiKeyResponse],
            dependencies=[Depends(require_role("admin", "editor"))])
async def list_api_keys(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    result = await db.execute(select(ApiKey).where(ApiKey.active == True))  # noqa: E712
    return result.scalars().all()


@router.delete("/api-keys/{key_id}", status_code=204,
               dependencies=[Depends(require_role("admin", "editor"))])
async def revoke_api_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.active = False
    await db.commit()
```

- [ ] **Step 2: Update existing auth tests to match new flow**

Rewrite `backend/tests/test_router_auth.py` to test OTP login instead of password login. Also update `conftest` helpers in other test files that use `create_signed_cookie` — they now need `(user_id, role, email)` args.

The key tests:
- Login with valid email sends OTP (mock email service)
- Login with invalid email returns 401
- Verify OTP with correct code sets cookie
- Verify OTP with wrong code returns 401
- Accept invite activates user
- /me returns current user
- API key endpoints require editor+ role

- [ ] **Step 3: Fix all other test files that use `create_signed_cookie`**

Search for `create_signed_cookie()` in all test files and update to `create_signed_cookie("test-user-id", "admin", "test@tatu.local")`.

- [ ] **Step 4: Run full test suite**

```bash
docker compose --profile test run --rm test -v
```

Fix any remaining failures from the auth change.

- [ ] **Step 5: Commit**

```bash
git add backend/app/routers/auth.py backend/tests/
git commit -m "feat: rewrite auth router for email OTP login flow"
```

---

### Task 8: Users router

**Files:**
- Create: `backend/app/routers/users.py`
- Modify: `backend/app/main.py` (register router)

- [ ] **Step 1: Write users router**

```python
# backend/app/routers/users.py
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_role, require_dashboard_auth, create_invite_token
from app.config import settings
from app.database import get_db
from app.schemas.user import UserInvite, UserUpdate, UserResponse
from app.services.user_service import (
    create_user, list_users, update_user, get_user_by_email,
)
from app.services.email_service import send_invite_email

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=list[UserResponse],
            dependencies=[Depends(require_role("admin", "editor"))])
async def list_users_endpoint(db: AsyncSession = Depends(get_db)):
    return await list_users(db)


@router.post("/invite", response_model=UserResponse, status_code=201)
async def invite_user(
    body: UserInvite,
    user_data: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    existing = await get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="User with this email already exists")

    inviter_id = uuid.UUID(user_data["user_id"])
    user = await create_user(
        db,
        email=body.email,
        name=body.name,
        role=body.role,
        active=False,
        invited_by=inviter_id,
    )
    token = create_invite_token(str(user.id))
    frontend_url = settings.cors_origins[0] if settings.cors_origins else "http://localhost:5173"
    invite_url = f"{frontend_url}/accept-invite?token={token}"
    inviter_name = user_data.get("email", "Admin")
    await send_invite_email(body.email, invite_url, inviter_name)
    return user


@router.put("/{user_id}", response_model=UserResponse,
            dependencies=[Depends(require_role("admin"))])
async def update_user_endpoint(
    user_id: uuid.UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
):
    user = await update_user(db, user_id, body)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.delete("/{user_id}", status_code=204,
               dependencies=[Depends(require_role("admin"))])
async def deactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    user = await update_user(db, user_id, UserUpdate(active=False))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
```

- [ ] **Step 2: Register router in main.py**

```python
from app.routers import users as users_router
# ...
app.include_router(users_router.router)
```

- [ ] **Step 3: Add admin bootstrap to lifespan**

In `backend/app/main.py`, after rule loading in the lifespan:

```python
from app.services.user_service import bootstrap_admin

# After rule loading block:
if settings.admin_email:
    async with async_session() as db:
        admin = await bootstrap_admin(db, settings.admin_email)
        if admin:
            print(f"Bootstrap admin created: {admin.email}")
```

- [ ] **Step 4: Write router tests**

```python
# backend/tests/test_router_users.py
# Test invite (admin only), list (admin+editor), update role, deactivate
# Mock email_service.send_invite_email to avoid SMTP in tests
```

- [ ] **Step 5: Run full test suite**

```bash
docker compose --profile test run --rm test -v
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/routers/users.py backend/app/main.py backend/tests/test_router_users.py
git commit -m "feat: add users router with invite, role management, and admin bootstrap"
```

---

### Task 9: Update rules router permissions

**Files:**
- Modify: `backend/app/routers/rules.py`

- [ ] **Step 1: Update rules router to use role-based auth**

Change `dependencies=[Depends(require_dashboard_auth)]` to `dependencies=[Depends(require_role("admin", "editor"))]` for write operations (POST, PUT, DELETE, clone). Keep GET (list/get) at `require_dashboard_auth` (all roles can view).

- [ ] **Step 2: Run full test suite**

```bash
docker compose --profile test run --rm test -v
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/routers/rules.py
git commit -m "feat: apply role-based permissions to rules router"
```

---

## Chunk 3: Frontend Auth & Users UI

### Task 10: Update frontend auth flow

**Files:**
- Modify: `frontend/src/hooks/useAuth.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/pages/Login.tsx`

- [ ] **Step 1: Add auth types**

Add to `frontend/src/lib/types.ts`:

```typescript
export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "editor" | "viewer";
}
```

- [ ] **Step 2: Update API client**

Replace the `login` method and add new auth methods:

```typescript
  login: (email: string) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email }) }),
  verifyOtp: (email: string, code: string) =>
    request("/auth/verify-otp", { method: "POST", body: JSON.stringify({ email, code }) }),
  getMe: () =>
    request("/auth/me"),
```

- [ ] **Step 3: Rewrite useAuth hook**

```typescript
// frontend/src/hooks/useAuth.ts
import { useState, useCallback } from "react";
import { api } from "../lib/api";
import type { AuthUser } from "../lib/types";

export function useAuth() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [otpSent, setOtpSent] = useState(false);
  const [loginEmail, setLoginEmail] = useState("");

  const sendOtp = useCallback(async (email: string) => {
    try {
      setError(null);
      await api.login(email);
      setLoginEmail(email);
      setOtpSent(true);
    } catch {
      setError("Invalid email or account inactive");
    }
  }, []);

  const verifyOtp = useCallback(async (code: string) => {
    try {
      setError(null);
      await api.verifyOtp(loginEmail, code);
      const me = (await api.getMe()) as AuthUser;
      setUser(me);
      setIsAuthenticated(true);
    } catch {
      setError("Invalid or expired code");
    }
  }, [loginEmail]);

  const checkAuth = useCallback(async () => {
    try {
      const me = (await api.getMe()) as AuthUser;
      setUser(me);
      setIsAuthenticated(true);
    } catch {
      setIsAuthenticated(false);
    }
  }, []);

  return { user, isAuthenticated, error, otpSent, sendOtp, verifyOtp, checkAuth };
}
```

- [ ] **Step 4: Rewrite Login page**

Two-step form: email entry → OTP entry. Use the `otpSent` state from useAuth to switch between steps.

- [ ] **Step 5: Update App.tsx**

Pass the new auth props. The `Login` component now needs `sendOtp`, `verifyOtp`, `otpSent`, and `error` instead of `onLogin`.

- [ ] **Step 6: Build and lint**

```bash
docker compose --profile build run --rm frontend-build
docker compose --profile lint run --rm frontend-lint
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/hooks/useAuth.ts frontend/src/lib/api.ts frontend/src/lib/types.ts frontend/src/pages/Login.tsx frontend/src/App.tsx
git commit -m "feat: rewrite frontend auth for email OTP two-step login"
```

---

### Task 11: Users management in Settings

**Files:**
- Modify: `frontend/src/lib/api.ts` (add user API methods)
- Modify: `frontend/src/pages/Settings.tsx` (add Users section)

- [ ] **Step 1: Add user API methods**

```typescript
  getUsers: () =>
    request("/users"),
  inviteUser: (body: { email: string; name: string; role: string }) =>
    request("/users/invite", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: { role?: string; active?: boolean }) =>
    request(`/users/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deactivateUser: (id: string) =>
    request(`/users/${id}`, { method: "DELETE" }),
```

- [ ] **Step 2: Add Users section to Settings page**

Below the API Keys section, add a Users table (visible to admin + editor). Admin sees:
- Invite form (email, name, role dropdown)
- Role dropdown on each user row
- Deactivate button

Get the user role from the auth context to conditionally render admin-only controls.

- [ ] **Step 3: Build and lint**

```bash
docker compose --profile build run --rm frontend-build
docker compose --profile lint run --rm frontend-lint
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/api.ts frontend/src/pages/Settings.tsx
git commit -m "feat: add Users management section to Settings page"
```

---

### Task 12: Accept Invite page

**Files:**
- Create: `frontend/src/pages/AcceptInvite.tsx`
- Modify: `frontend/src/App.tsx` (add route)

- [ ] **Step 1: Create AcceptInvite page**

Reads `?token=xxx` from URL, calls `GET /api/v1/auth/accept-invite?token=xxx`, shows success message with link to login, or error message.

- [ ] **Step 2: Add route in App.tsx**

The accept-invite route must be accessible without authentication (it's for new users). Add it outside the `DashboardLayout` route:

```tsx
<Route path="accept-invite" element={<AcceptInvite />} />
```

Note: This route needs to be accessible even when not authenticated, so it should be placed in the BrowserRouter but handled separately from the auth check.

- [ ] **Step 3: Build and lint**

```bash
docker compose --profile build run --rm frontend-build
docker compose --profile lint run --rm frontend-lint
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/pages/AcceptInvite.tsx frontend/src/App.tsx
git commit -m "feat: add AcceptInvite page for invitation flow"
```

---

### Task 13: Full integration verification

- [ ] **Step 1: Run all backend tests**

```bash
docker compose --profile test run --rm test -v
```

Expected: All tests PASS

- [ ] **Step 2: Build frontend**

```bash
docker compose --profile build run --rm frontend-build
```

Expected: Build succeeds

- [ ] **Step 3: Lint frontend**

```bash
docker compose --profile lint run --rm frontend-lint
```

Expected: No errors

- [ ] **Step 4: Smoke test with Mailpit**

```bash
make dev
# Open http://localhost:5173 — should see email login form
# Open http://localhost:8025 — Mailpit web UI to see OTP emails
# Login with admin email, check Mailpit for OTP code, enter code
```

- [ ] **Step 5: Test role-based access**

- Admin can see Users section and invite new users
- Editor can see Users list (read-only) and edit rules
- Viewer can view dashboard but not edit rules or see Users

- [ ] **Step 6: Final commit if adjustments needed**

```bash
git add -A && git commit -m "fix: address integration issues from smoke test"
```
