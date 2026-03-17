from pydantic import BaseModel
from typing import Literal


class RuleCreate(BaseModel):
    id: str
    name: str
    format: Literal["yaml", "yara"]
    content: str
    category: str
    severity: Literal["critical", "warning", "info"]
    mode: Literal["audit", "strict"] = "audit"
    action: Literal["block", "warn", "log"]
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ]
    matcher: str


class RuleUpdate(BaseModel):
    name: str | None = None
    content: str | None = None
    category: str | None = None
    severity: Literal["critical", "warning", "info"] | None = None
    mode: Literal["audit", "strict"] | None = None
    action: Literal["block", "warn", "log"] | None = None
    hook_event: Literal[
        "PreToolUse", "PostToolUse", "Stop", "SessionStart",
        "SessionEnd", "UserPromptSubmit", "Notification", "PreCompact",
    ] | None = None
    matcher: str | None = None
    enabled: bool | None = None


class RuleResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    format: str
    content: str
    source: str
    enabled: bool
    category: str
    severity: str
    mode: str
    action: str
    hook_event: str
    matcher: str
    version_added: int


class RuleSyncItem(BaseModel):
    id: str
    format: str
    content: str


class RuleSyncResponse(BaseModel):
    version: int
    updated_at: str
    rules: list[RuleSyncItem]


class RuleSyncUpToDate(BaseModel):
    version: int
    status: str = "up_to_date"
