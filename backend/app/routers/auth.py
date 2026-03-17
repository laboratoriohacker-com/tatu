import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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
from app.services.user_service import get_user_by_email, get_user_by_id, activate_user
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
    response.set_cookie(key=COOKIE_NAME, value=cookie_value, max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax")
    return OtpVerifyResponse(user_id=str(user.id), role=user.role)

@router.get("/me", response_model=UserResponse)
async def get_current_user(user_data: dict = Depends(require_dashboard_auth), db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, uuid.UUID(user_data["user_id"]))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME)
    return {"message": "logged_out"}


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
    api_key = ApiKey(id=uuid.uuid4(), key_hash=hash_api_key(raw_key), label=body.label, created_at=datetime.now(timezone.utc), active=True)
    db.add(api_key)
    await db.commit()
    return ApiKeyCreateResponse(id=api_key.id, label=api_key.label, api_key=raw_key)

@router.get("/api-keys", response_model=list[ApiKeyResponse],
            dependencies=[Depends(require_role("admin", "editor"))])
async def list_api_keys(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.active == True))
    return result.scalars().all()

@router.delete("/api-keys/{key_id}", status_code=204,
               dependencies=[Depends(require_role("admin", "editor"))])
async def revoke_api_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.active = False
    await db.commit()
