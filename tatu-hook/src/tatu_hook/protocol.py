"""Claude Code hook protocol: stdin parsing and stdout/stderr responses."""
from __future__ import annotations

import json
import os
import sys


def _debug_log(msg: str) -> None:
    """Write debug info to a log file when TATU_DEBUG is set."""
    if not os.environ.get("TATU_DEBUG"):
        return
    log_path = os.path.expanduser("~/.tatu/debug.log")
    with open(log_path, "a") as f:
        f.write(msg + "\n")


def parse_hook_input(raw: str) -> dict:
    data = json.loads(raw)
    _debug_log(f"RAW INPUT: {json.dumps(data, indent=2, default=str)[:2000]}")
    return {
        "hook_event": data.get("hook_event_name", ""),
        "tool_name": data.get("tool_name", ""),
        "tool_input": data.get("tool_input", {}),
        "tool_response": data.get("tool_response", {}),
        "session_id": data.get("session_id", ""),
        "cwd": data.get("cwd", ""),
        "raw": data,
    }


def extract_content(hook_input: dict) -> str:
    """Extract scannable content from Claude Code hook input."""
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    tool_response = hook_input.get("tool_response", {})
    hook_event = hook_input.get("hook_event", "")

    parts = []

    if isinstance(tool_input, dict):
        if tool_name in ("Write", "Read"):
            content = tool_input.get("content", "")
            if content:
                parts.append(content)
            file_path = tool_input.get("file_path", "")
            # Pre-scan: read file from disk for Read at PreToolUse
            # File content is appended before file_path so line numbers align with actual file lines
            if tool_name == "Read" and hook_event == "PreToolUse" and file_path:
                resolved = file_path
                if not os.path.isabs(resolved):
                    cwd = hook_input.get("cwd", "")
                    if cwd:
                        resolved = os.path.join(cwd, resolved)
                try:
                    size = os.path.getsize(resolved)
                    if size <= 1_048_576:  # 1MB limit
                        with open(resolved, encoding="utf-8") as f:
                            file_content = f.read()
                        parts.append(file_content)
                except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError):
                    pass  # skip pre-scan, allow Claude Code to handle
            if file_path:
                parts.append(file_path)
        elif tool_name in ("Edit", "MultiEdit"):
            for key in ("content", "old_string", "new_string"):
                val = tool_input.get(key, "")
                if isinstance(val, str) and val.strip():
                    parts.append(val)
            file_path = tool_input.get("file_path", "")
            if file_path:
                parts.append(file_path)
        elif tool_name == "Bash":
            cmd = tool_input.get("command", "")
            if cmd:
                parts.append(cmd)
        else:
            content = tool_input.get("content", "")
            if content:
                parts.append(content)

    # For PostToolUse, also scan tool_response
    if hook_event == "PostToolUse" and isinstance(tool_response, dict):
        for key in ("stdout", "stderr", "content"):
            val = tool_response.get(key, "")
            if isinstance(val, str) and val.strip():
                parts.append(val)
        # Read tool nests content under tool_response.file.content
        file_block = tool_response.get("file")
        if isinstance(file_block, dict):
            val = file_block.get("content", "")
            if isinstance(val, str) and val.strip():
                parts.append(val)

    return "\n".join(parts)


def format_allow_response(hook_event: str, context: str | None = None) -> str:
    if hook_event == "PreToolUse":
        out: dict = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }
        if context:
            out["hookSpecificOutput"]["permissionDecisionReason"] = context
        return json.dumps(out)
    out = {"hookSpecificOutput": {"hookEventName": hook_event}}
    if context:
        out["hookSpecificOutput"]["additionalContext"] = context
    return json.dumps(out)


def format_deny_response(hook_event: str, reason: str) -> str:
    if hook_event == "PreToolUse":
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
    return json.dumps({
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": hook_event},
    })


def format_audit_response(hook_event: str, context: str) -> str:
    """Audit mode: allow but include context about what would have been blocked."""
    if hook_event == "PreToolUse":
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": context,
            }
        })
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": context,
        }
    })
