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
            OtpCode.used == False,
            OtpCode.expires_at > datetime.now(timezone.utc),
        )
    )
    otp = result.scalar_one_or_none()
    if not otp:
        return False
    otp.used = True
    await db.commit()
    return True
