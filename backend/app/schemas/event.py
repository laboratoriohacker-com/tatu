from datetime import datetime
from uuid import UUID
from typing import Any, Literal
from pydantic import BaseModel


class EventCreate(BaseModel):
    hook_name: str
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ]
    severity: Literal["critical", "warning", "info"]
    status: Literal["blocked", "warning", "allowed", "clean", "audit_block"]
    message: str
    developer: str
    repository: str
    session_id: str
    tool_name: str | None = None
    metadata: dict[str, Any] = {}


class EventResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    timestamp: datetime
    hook_name: str
    hook_event: str
    severity: str
    status: str
    message: str
    developer: str
    repository: str
    session_id: str
    tool_name: str | None
    metadata_: dict[str, Any]
