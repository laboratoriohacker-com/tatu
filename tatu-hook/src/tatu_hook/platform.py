"""Platform abstraction for IDE-specific hook differences."""
from __future__ import annotations

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
