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

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

COOKIE_NAME = "tatu_session"
COOKIE_MAX_AGE = 86400  # 24 hours

_serializer = URLSafeTimedSerializer(settings.secret_key)

# --- API Key functions (KEEP UNCHANGED) ---
def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()

def verify_api_key(raw_key: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key), hashed)

def generate_api_key() -> str:
    return f"tatu_{secrets.token_urlsafe(32)}"

async def require_api_key(request: Request, db: AsyncSession = Depends(get_db)) -> ApiKey:
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

# --- NEW: Session cookie with user data ---
def create_signed_cookie(user_id: str, role: str, email: str) -> str:
    return _serializer.dumps({"user_id": user_id, "role": role, "email": email, "t": int(time.time())})

def decode_signed_cookie(cookie_value: str) -> dict | None:
    try:
        return _serializer.loads(cookie_value, max_age=COOKIE_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None

# --- NEW: Invite token ---
def create_invite_token(user_id: str) -> str:
    return _serializer.dumps({"user_id": user_id, "purpose": "invite"})

def decode_invite_token(token: str) -> dict | None:
    try:
        data = _serializer.loads(token, max_age=86400)
        if data.get("purpose") != "invite":
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None

# --- NEW: Dashboard auth with user data ---
async def require_dashboard_auth(request: Request) -> dict:
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    data = decode_signed_cookie(cookie)
    if not data or "user_id" not in data:
        raise HTTPException(status_code=401, detail="Not authenticated")
    request.state.user = data
    return data

def require_role(*roles: str):
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
