"""Tests for platform abstraction module."""
from __future__ import annotations

import os

from tatu_hook.platform import resolve_config_path, PLATFORMS, get_hook_entries, has_tatu_hook


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
