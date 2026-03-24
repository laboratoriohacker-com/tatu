"""Tests for platform abstraction module."""
from __future__ import annotations

import os

from tatu_hook.platform import resolve_config_path, PLATFORMS


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
