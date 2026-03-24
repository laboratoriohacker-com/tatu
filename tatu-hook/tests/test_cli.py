"""Tests for tatu-hook CLI run_hook core logic."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from tatu_hook.cli import run_hook, register_hooks, register_hooks_cursor
from tatu_hook.platform import has_tatu_hook
from tatu_hook.sync import save_manifest, save_rules_to_cache

STRICT_BLOCK_RULE = """id: test-block
info:
  name: Test Block
  severity: critical
  category: secrets
hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: strict
detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'
message: "AWS key detected"
"""

AUDIT_BLOCK_RULE = """id: test-audit
info:
  name: Test Audit
  severity: critical
  category: secrets
hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit
detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'
message: "AWS key detected (audit)"
"""

WARN_RULE = """id: test-warn
info:
  name: Test Warn
  severity: medium
  category: quality
hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: strict
detect:
  type: regex
  patterns:
    - 'TODO'
message: "TODO comment found"
"""

CPF_BLOCK_RULE = """id: test-cpf
info:
  name: Test CPF
  severity: critical
  category: pii
hook:
  events:
    - PreToolUse
    - PostToolUse
  matcher: Write|Edit|Read
  action: block
  mode: strict
detect:
  type: regex
  patterns:
    - '\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b'
message: "CPF detected"
"""

CPF_AUDIT_RULE = """id: test-cpf-audit
info:
  name: Test CPF Audit
  severity: critical
  category: pii
hook:
  events:
    - PreToolUse
  matcher: Read
  action: block
  mode: audit
detect:
  type: regex
  patterns:
    - '\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b'
message: "CPF detected (audit)"
"""

AWS_KEY_CONTENT = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Write",
    "tool_input": {
        "file_path": "/tmp/config.py",
        "content": "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
    },
})

CLEAN_CONTENT = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Write",
    "tool_input": {
        "file_path": "/tmp/hello.py",
        "content": "print('hello world')",
    },
})

BASH_AWS_KEY_CONTENT = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {
        "command": "echo AKIAIOSFODNN7EXAMPLE",
    },
})

TODO_CONTENT = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Write",
    "tool_input": {
        "file_path": "/tmp/code.py",
        "content": "# TODO: fix this later",
    },
})


def _setup_dir(tmpdir: str, rule_yaml: str) -> str:
    manifest = {
        "version": 1,
        "api_url": "",
        "api_key": "",
        "updated_at": "",
        "rule_count": 1,
    }
    save_manifest(tmpdir, manifest)
    save_rules_to_cache(tmpdir, [{"id": "test-rule", "format": "yaml", "content": rule_yaml}])
    return tmpdir


class TestRunHookStrictBlock:
    def test_matching_content_returns_deny(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "deny"
        assert "AWS key detected" in result["context"]

    def test_deny_context_is_rule_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert "AWS key detected" in result["context"]
        assert "Detected at line 1" in result["context"]


class TestRunHookAuditBlock:
    def test_matching_content_returns_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, AUDIT_BLOCK_RULE)
            result = run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "allow"

    def test_audit_context_contains_audit_prefix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, AUDIT_BLOCK_RULE)
            result = run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert result["context"] is not None
        assert result["context"].startswith("[AUDIT]")

    def test_audit_context_contains_rule_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, AUDIT_BLOCK_RULE)
            result = run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert "AWS key detected (audit)" in result["context"]


class TestRunHookNoMatch:
    def test_clean_content_returns_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", CLEAN_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "allow"

    def test_clean_content_context_is_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", CLEAN_CONTENT, tatu_dir=tmpdir)

        assert result["context"] is None


class TestRunHookWrongTool:
    def test_rule_matches_write_but_tool_is_bash_returns_allow(self):
        """Rule matcher is Write|Edit but tool is Bash — should not match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", BASH_AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "allow"

    def test_wrong_tool_context_is_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            result = run_hook("pre", BASH_AWS_KEY_CONTENT, tatu_dir=tmpdir)

        assert result["context"] is None


class TestRunHookWarnAction:
    def test_warn_match_returns_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, WARN_RULE)
            result = run_hook("pre", TODO_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "allow"

    def test_warn_context_contains_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, WARN_RULE)
            result = run_hook("pre", TODO_CONTENT, tatu_dir=tmpdir)

        assert result["context"] == "TODO comment found"


class TestRunHookNoRules:
    def test_empty_rules_returns_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = {"version": 0, "api_url": "", "api_key": "", "updated_at": "", "rule_count": 0}
            save_manifest(tmpdir, manifest)
            result = run_hook("pre", CLEAN_CONTENT, tatu_dir=tmpdir)

        assert result["decision"] == "allow"
        assert result["context"] is None


class TestRunHookLineNumbers:
    def test_deny_message_includes_line_numbers(self, tmp_path):
        """Strict block should append line numbers to deny message."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        target = tmp_path / "data.txt"
        cpf1 = "928.385." + "640-64"
        cpf2 = "111.222." + "333-44"
        target.write_text(f"safe\n{cpf1}\nsafe\n{cpf2}\n")

        raw_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(tmp_path),
        })
        result = run_hook("pre", raw_input, tatu_dir=tatu_dir)

        assert result["decision"] == "deny"
        assert "lines 2, 4" in result["context"]
        assert "Ask the developer to provide a redacted version" in result["context"]

    def test_audit_message_includes_line_numbers(self, tmp_path):
        """Audit block should append line numbers to audit context."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_AUDIT_RULE)

        target = tmp_path / "data.txt"
        cpf1 = "928.385." + "640-64"
        target.write_text(f"safe\n{cpf1}\nsafe\n")

        raw_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(tmp_path),
        })
        result = run_hook("pre", raw_input, tatu_dir=tatu_dir)

        assert result["decision"] == "allow"
        assert "[AUDIT]" in result["context"]
        assert "line 2" in result["context"]


class TestRunHookReadPreScan:
    def test_read_prescan_blocks_cpf_at_pretooluse(self, tmp_path):
        """End-to-end: Read of file with CPF is blocked at PreToolUse."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        target = tmp_path / "client_data.txt"
        target.write_text(
            "Client: João Silva\n"
            "CPF: " + "928.385." + "640-64" + "\n"
            "Email: joao@example.com\n"
        )

        raw_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(tmp_path),
        })
        result = run_hook("pre", raw_input, tatu_dir=tatu_dir)

        assert result["decision"] == "deny"
        assert "CPF detected" in result["context"]
        assert "line 2" in result["context"]

    def test_read_prescan_allows_clean_file(self, tmp_path):
        """Clean file should be allowed through."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        target = tmp_path / "clean.txt"
        target.write_text("No sensitive data here.\n")

        raw_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(tmp_path),
        })
        result = run_hook("pre", raw_input, tatu_dir=tatu_dir)

        assert result["decision"] == "allow"
        assert result["context"] is None


# ---------------------------------------------------------------------------
# register_hooks
# ---------------------------------------------------------------------------

class TestRegisterHooks:
    def test_register_hooks_empty_file(self, tmp_path, monkeypatch):
        """Creates settings file with all 3 hook entries."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        path, modified = register_hooks("global")

        assert modified is True
        assert os.path.exists(path)
        data = json.loads(settings_file.read_text())
        assert "SessionStart" in data["hooks"]
        assert "PreToolUse" in data["hooks"]
        assert "PostToolUse" in data["hooks"]
        assert len(data["hooks"]["SessionStart"]) == 1
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert len(data["hooks"]["PostToolUse"]) == 1

    def test_register_hooks_preserves_existing_settings(self, tmp_path, monkeypatch):
        """Preserves other settings, adds hooks."""
        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.json"
        settings_file.write_text(json.dumps({"model": "opus", "other": True}))
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        path, modified = register_hooks("global")

        data = json.loads(settings_file.read_text())
        assert data["model"] == "opus"
        assert data["other"] is True
        assert "hooks" in data
        assert modified is True

    def test_register_hooks_dedup(self, tmp_path, monkeypatch):
        """No duplicate entries on re-run."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        _, modified1 = register_hooks("global")
        _, modified2 = register_hooks("global")

        assert modified1 is True
        assert modified2 is False
        data = json.loads(settings_file.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_register_hooks_preserves_existing_hooks(self, tmp_path, monkeypatch):
        """Preserves existing hooks from other tools."""
        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.json"
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-other-hook"}]}
                ]
            }
        }
        settings_file.write_text(json.dumps(existing))
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        register_hooks("global")

        data = json.loads(settings_file.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 2
        commands = []
        for entry in data["hooks"]["PreToolUse"]:
            for h in entry.get("hooks", []):
                commands.append(h.get("command", ""))
        assert "my-other-hook" in commands
        assert "tatu-hook run --event pre" in commands

    def test_register_hooks_creates_parent_dir(self, tmp_path, monkeypatch):
        """Creates .claude/ directory if missing."""
        settings_file = tmp_path / "new_dir" / ".claude" / "settings.json"
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        path, modified = register_hooks("global")

        assert modified is True
        assert os.path.exists(path)

    def test_register_hooks_invalid_json(self, tmp_path, monkeypatch):
        """Invalid JSON raises JSONDecodeError."""
        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.json"
        settings_file.write_text("{ not valid json")
        monkeypatch.setattr("tatu_hook.cli.resolve_config_path", lambda platform, scope: str(settings_file))

        with pytest.raises(json.JSONDecodeError):
            register_hooks("global")


class TestHasTatuHook:
    def test_detects_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "tatu-hook run --event pre"}]}
        ]
        assert has_tatu_hook("claude", entries) is True

    def test_no_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "other-hook"}]}
        ]
        assert has_tatu_hook("claude", entries) is False

    def test_empty_entries(self):
        assert has_tatu_hook("claude", []) is False

    def test_detects_custom_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "tatu-hook run --event pre --tatu-dir /custom"}]}
        ]
        assert has_tatu_hook("claude", entries) is True


# ---------------------------------------------------------------------------
# register_hooks_cursor
# ---------------------------------------------------------------------------

class TestRegisterHooksCursor:
    def test_register_cursor_hooks_creates_file(self, tmp_path, monkeypatch):
        """Creates hooks.json with 5 hook events."""
        hooks_file = tmp_path / ".cursor" / "hooks.json"
        monkeypatch.setattr(
            "tatu_hook.cli.resolve_config_path",
            lambda platform, scope: str(hooks_file),
        )
        path, modified = register_hooks_cursor("global")
        assert modified is True
        assert os.path.exists(path)
        data = json.loads(hooks_file.read_text())
        assert data["version"] == 1
        assert set(data["hooks"].keys()) == {
            "sessionStart", "preToolUse", "postToolUse",
            "beforeShellExecution", "beforeReadFile",
        }

    def test_register_cursor_hooks_preserves_existing(self, tmp_path, monkeypatch):
        """Preserves existing hooks from other tools."""
        hooks_dir = tmp_path / ".cursor"
        hooks_dir.mkdir()
        hooks_file = hooks_dir / "hooks.json"
        existing = {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"type": "command", "command": "other-hook"}
                ]
            }
        }
        hooks_file.write_text(json.dumps(existing))
        monkeypatch.setattr(
            "tatu_hook.cli.resolve_config_path",
            lambda platform, scope: str(hooks_file),
        )
        register_hooks_cursor("global")
        data = json.loads(hooks_file.read_text())
        assert len(data["hooks"]["preToolUse"]) == 2
        commands = [e["command"] for e in data["hooks"]["preToolUse"]]
        assert "other-hook" in commands
        assert "tatu-hook run --event pre" in commands

    def test_register_cursor_hooks_dedup(self, tmp_path, monkeypatch):
        """No duplicate entries on re-run."""
        hooks_file = tmp_path / ".cursor" / "hooks.json"
        monkeypatch.setattr(
            "tatu_hook.cli.resolve_config_path",
            lambda platform, scope: str(hooks_file),
        )
        _, mod1 = register_hooks_cursor("global")
        _, mod2 = register_hooks_cursor("global")
        assert mod1 is True
        assert mod2 is False


# ---------------------------------------------------------------------------
# pre-shell / pre-read events
# ---------------------------------------------------------------------------

CURSOR_SHELL_INPUT = json.dumps({
    "hook_event_name": "beforeShellExecution",
    "command": "rm -rf /",
    "cwd": "/project",
    "session_id": "cursor-sess-1",
    "cursor_version": "1.0.0",
})

DESTRUCTIVE_CMD_RULE = """id: test-rm-rf
info:
  name: rm -rf Protection
  severity: critical
  category: destructive
hook:
  event: PreToolUse
  matcher: Bash
  action: block
  mode: strict
detect:
  type: regex
  patterns:
    - 'rm\\s+-(r|f|rf|fr)\\s'
message: "Destructive rm command detected"
"""


class TestRunHookPreShell:
    def test_pre_shell_blocks_destructive_command(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, DESTRUCTIVE_CMD_RULE)
            result = run_hook("pre-shell", CURSOR_SHELL_INPUT, tatu_dir=tmpdir)
        assert result["decision"] == "deny"
        assert "Destructive" in result["context"] or "rm" in result["context"].lower()

    def test_pre_shell_allows_safe_command(self):
        safe_input = json.dumps({
            "hook_event_name": "beforeShellExecution",
            "command": "ls -la",
            "cwd": "/project",
            "session_id": "cursor-sess-2",
            "cursor_version": "1.0.0",
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, DESTRUCTIVE_CMD_RULE)
            result = run_hook("pre-shell", safe_input, tatu_dir=tmpdir)
        assert result["decision"] == "allow"


class TestRunHookPreRead:
    def test_pre_read_blocks_file_with_cpf(self, tmp_path):
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        cursor_input = json.dumps({
            "hook_event_name": "beforeReadFile",
            "file_path": str(tmp_path / "data.txt"),
            "content": "Client CPF: " + "928.385." + "640-64",
            "session_id": "cursor-sess-3",
            "cursor_version": "1.0.0",
        })
        result = run_hook("pre-read", cursor_input, tatu_dir=tatu_dir)
        assert result["decision"] == "deny"
        assert "CPF" in result["context"]

    def test_pre_read_allows_clean_content(self, tmp_path):
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        cursor_input = json.dumps({
            "hook_event_name": "beforeReadFile",
            "file_path": str(tmp_path / "clean.txt"),
            "content": "No sensitive data here",
            "session_id": "cursor-sess-4",
            "cursor_version": "1.0.0",
        })
        result = run_hook("pre-read", cursor_input, tatu_dir=tatu_dir)
        assert result["decision"] == "allow"


# ---------------------------------------------------------------------------
# platform metadata in event reporting
# ---------------------------------------------------------------------------

from unittest.mock import patch


class TestEventReportingPlatform:
    def test_cursor_events_include_platform_metadata(self):
        """Events from Cursor input should include platform=cursor in metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, DESTRUCTIVE_CMD_RULE)
            with patch("tatu_hook.cli.report_event") as mock_report:
                run_hook("pre-shell", CURSOR_SHELL_INPUT, tatu_dir=tmpdir)
                if mock_report.called:
                    event_data = mock_report.call_args[0][2]
                    assert event_data["metadata"]["platform"] == "cursor"

    def test_claude_events_include_platform_metadata(self):
        """Events from Claude Code input should include platform=claude in metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_dir(tmpdir, STRICT_BLOCK_RULE)
            with patch("tatu_hook.cli.report_event") as mock_report:
                run_hook("pre", AWS_KEY_CONTENT, tatu_dir=tmpdir)
                if mock_report.called:
                    event_data = mock_report.call_args[0][2]
                    assert event_data["metadata"]["platform"] == "claude"
