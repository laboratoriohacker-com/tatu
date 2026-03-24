"""Tests for platform abstraction module."""
from __future__ import annotations

import json
import os

from tatu_hook.platform import (
    resolve_config_path, PLATFORMS, get_hook_entries, has_tatu_hook,
    detect_platform, format_cursor_allow, format_cursor_deny,
)


def test_claude_global_config_path():
    path = resolve_config_path("claude", "global")
    assert path == os.path.expanduser("~/.claude/settings.json")


def test_claude_project_config_path(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/project")
    path = resolve_config_path("claude", "project")
    assert path == "/project/.claude/settings.json"


def test_cursor_global_config_path():
    path = resolve_config_path("cursor", "global")
    assert path == os.path.expanduser("~/.cursor/hooks.json")


def test_cursor_project_config_path(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/project")
    path = resolve_config_path("cursor", "project")
    assert path == "/project/.cursor/hooks.json"


def test_platforms_has_claude_and_cursor():
    assert "claude" in PLATFORMS
    assert "cursor" in PLATFORMS


def test_claude_hook_entries_has_3_events():
    entries = get_hook_entries("claude")
    assert set(entries.keys()) == {"SessionStart", "PreToolUse", "PostToolUse"}


def test_cursor_hook_entries_has_5_events():
    entries = get_hook_entries("cursor")
    assert set(entries.keys()) == {
        "sessionStart", "preToolUse", "postToolUse",
        "beforeShellExecution", "beforeReadFile",
    }


def test_cursor_hook_entry_format():
    entries = get_hook_entries("cursor")
    entry = entries["preToolUse"][0]
    assert entry["type"] == "command"
    assert "tatu-hook run" in entry["command"]


def test_claude_hook_entry_format():
    entries = get_hook_entries("claude")
    entry = entries["PreToolUse"]
    assert "hooks" in entry
    assert entry["hooks"][0]["type"] == "command"


def test_has_tatu_hook_claude_format():
    entries = [
        {"hooks": [{"type": "command", "command": "tatu-hook run --event pre"}]}
    ]
    assert has_tatu_hook("claude", entries) is True


def test_has_tatu_hook_cursor_format():
    entries = [
        {"type": "command", "command": "tatu-hook run --event pre"}
    ]
    assert has_tatu_hook("cursor", entries) is True


def test_has_tatu_hook_empty():
    assert has_tatu_hook("claude", []) is False
    assert has_tatu_hook("cursor", []) is False


def test_detect_cursor_by_cursor_version():
    data = {"cursor_version": "1.0.0", "hook_event_name": "preToolUse"}
    assert detect_platform(data) == "cursor"


def test_detect_claude_without_cursor_version():
    data = {"hook_event_name": "PreToolUse", "tool_name": "Write"}
    assert detect_platform(data) == "claude"


def test_detect_cursor_by_camelcase_event():
    data = {"hook_event_name": "preToolUse"}
    assert detect_platform(data) == "cursor"


def test_detect_cursor_before_shell_execution():
    data = {"hook_event_name": "beforeShellExecution", "command": "ls"}
    assert detect_platform(data) == "cursor"


def test_detect_platform_empty_input():
    assert detect_platform({}) == "claude"


def test_format_cursor_allow_pretooluse():
    result = json.loads(format_cursor_allow("preToolUse"))
    assert result["permission"] == "allow"


def test_format_cursor_allow_with_context():
    result = json.loads(format_cursor_allow("postToolUse", context="scan ok"))
    assert result["additional_context"] == "scan ok"


def test_format_cursor_allow_session_start():
    result = json.loads(format_cursor_allow("sessionStart", context="Synced 46 rule(s)."))
    assert result["additional_context"] == "Synced 46 rule(s)."


def test_format_cursor_deny_pretooluse():
    result = json.loads(format_cursor_deny("preToolUse", "[BLOCKED] Secret found"))
    assert result["permission"] == "deny"
    assert result["user_message"] == "[BLOCKED] Secret found"
    assert result["agent_message"] == "[BLOCKED] Secret found"


def test_format_cursor_deny_before_shell():
    result = json.loads(format_cursor_deny("beforeShellExecution", "Destructive command"))
    assert result["permission"] == "deny"
    assert result["user_message"] == "Destructive command"


def test_format_cursor_deny_before_read():
    result = json.loads(format_cursor_deny("beforeReadFile", "PII in file"))
    assert result["permission"] == "deny"
    assert result["user_message"] == "PII in file"
