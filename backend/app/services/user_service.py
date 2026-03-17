import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User
from app.schemas.user import UserUpdate


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await db.get(User, user_id)


async def list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


async def create_user(
    db: AsyncSession, email: str, name: str, role: str = "viewer",
    active: bool = False, invited_by: uuid.UUID | None = None,
) -> User:
    user = User(id=uuid.uuid4(), email=email, name=name, role=role, active=active, invited_by=invited_by)
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
    result = await db.execute(select(User).limit(1))
    if result.scalars().first() is not None:
        return None
    return await create_user(db, email=admin_email, name="Admin", role="admin", active=True)
