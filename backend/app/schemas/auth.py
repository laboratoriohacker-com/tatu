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
