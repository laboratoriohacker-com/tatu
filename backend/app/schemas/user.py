from datetime import datetime
from uuid import UUID
from typing import Literal
from pydantic import BaseModel


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
