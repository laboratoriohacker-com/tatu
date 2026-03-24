"""Platform abstraction for IDE-specific hook differences."""
from __future__ import annotations

import json
import os


PLATFORMS = ("claude", "cursor")

# Tool name normalization: Cursor -> internal
_CURSOR_TOOL_MAP = {
    "Shell": "Bash",
}


def resolve_config_path(platform: str, scope: str) -> str:
    """Resolve the hooks config file path for a given platform and scope."""
    if platform == "claude":
        if scope == "project":
            return os.path.join(os.getcwd(), ".claude", "settings.json")
        return os.path.expanduser(os.path.join("~", ".claude", "settings.json"))
    # cursor
    if scope == "project":
        return os.path.join(os.getcwd(), ".cursor", "hooks.json")
    return os.path.expanduser(os.path.join("~", ".cursor", "hooks.json"))


def normalize_tool_name(platform: str, tool_name: str) -> str:
    """Normalize tool names to internal convention."""
    if platform == "cursor":
        return _CURSOR_TOOL_MAP.get(tool_name, tool_name)
    return tool_name


# Claude Code hook entries (existing format from cli.py)
_CLAUDE_HOOK_ENTRIES: dict = {
    "SessionStart": {
        "hooks": [{"type": "command", "command": "tatu-hook run --event session-start"}],
    },
    "PreToolUse": {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": "tatu-hook run --event pre"}],
    },
    "PostToolUse": {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": "tatu-hook run --event post"}],
    },
}

# Cursor hook entries (flat array format)
_CURSOR_HOOK_ENTRIES: dict = {
    "sessionStart": [
        {"type": "command", "command": "tatu-hook run --event session-start"},
    ],
    "preToolUse": [
        {"type": "command", "command": "tatu-hook run --event pre"},
    ],
    "postToolUse": [
        {"type": "command", "command": "tatu-hook run --event post"},
    ],
    "beforeShellExecution": [
        {"type": "command", "command": "tatu-hook run --event pre-shell"},
    ],
    "beforeReadFile": [
        {"type": "command", "command": "tatu-hook run --event pre-read"},
    ],
}


def get_hook_entries(platform: str) -> dict:
    """Return the hook registration entries for a platform."""
    if platform == "cursor":
        return _CURSOR_HOOK_ENTRIES
    return _CLAUDE_HOOK_ENTRIES


def has_tatu_hook(platform: str, entries: list) -> bool:
    """Check if tatu-hook is already registered in a hook event array."""
    if platform == "cursor":
        for entry in entries:
            if "tatu-hook run" in entry.get("command", ""):
                return True
        return False
    # Claude Code: nested under entry.hooks[].command
    for entry in entries:
        for hook_obj in entry.get("hooks", []):
            if "tatu-hook run" in hook_obj.get("command", ""):
                return True
    return False


def detect_platform(data: dict) -> str:
    """Detect platform from raw hook input JSON."""
    if "cursor_version" in data:
        return "cursor"
    event = data.get("hook_event_name", "")
    if event and event[0].islower():
        return "cursor"
    return "claude"


def format_cursor_allow(event: str, context: str | None = None) -> str:
    """Format a Cursor allow response."""
    if event in ("preToolUse", "beforeShellExecution", "beforeReadFile"):
        out: dict = {"permission": "allow"}
        if context:
            out["agent_message"] = context
        return json.dumps(out)
    # sessionStart, postToolUse
    out = {}
    if context:
        out["additional_context"] = context
    return json.dumps(out)


def format_cursor_deny(event: str, reason: str) -> str:
    """Format a Cursor deny response."""
    return json.dumps({
        "permission": "deny",
        "user_message": reason,
        "agent_message": reason,
    })
