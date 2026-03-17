import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_role, create_invite_token
from app.config import settings
from app.database import get_db
from app.schemas.user import UserInvite, UserUpdate, UserResponse
from app.services.user_service import create_user, list_users, update_user, get_user_by_email
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
    user = await create_user(db, email=body.email, name=body.name, role=body.role, active=False, invited_by=inviter_id)
    token = create_invite_token(str(user.id))
    frontend_url = settings.cors_origins[0] if settings.cors_origins else "http://localhost:5173"
    invite_url = f"{frontend_url}/accept-invite?token={token}"
    inviter_name = user_data.get("email", "Admin")
    await send_invite_email(body.email, invite_url, inviter_name)
    return user


@router.put("/{user_id}", response_model=UserResponse,
            dependencies=[Depends(require_role("admin"))])
async def update_user_endpoint(user_id: uuid.UUID, body: UserUpdate, db: AsyncSession = Depends(get_db)):
    user = await update_user(db, user_id, body)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.delete("/{user_id}", status_code=204,
               dependencies=[Depends(require_role("admin"))])
async def deactivate_user(user_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    user = await update_user(db, user_id, UserUpdate(active=False))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
