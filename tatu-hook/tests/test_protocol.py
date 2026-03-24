"""Tests for the Claude Code hook protocol module."""
from __future__ import annotations

import json

import pytest

from tatu_hook.protocol import (
    extract_content,
    format_allow_response,
    format_audit_response,
    format_deny_response,
    parse_hook_input,
)


# ---------------------------------------------------------------------------
# parse_hook_input
# ---------------------------------------------------------------------------

def test_parse_hook_input_pretooluse():
    raw = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/test.py", "content": "print('hello')"},
        "tool_response": {},
    })
    result = parse_hook_input(raw)
    assert result["hook_event"] == "PreToolUse"
    assert result["tool_name"] == "Write"
    assert result["tool_input"]["file_path"] == "/tmp/test.py"
    assert result["tool_input"]["content"] == "print('hello')"
    assert result["raw"]["hook_event_name"] == "PreToolUse"


def test_parse_hook_input_missing_fields():
    raw = json.dumps({})
    result = parse_hook_input(raw)
    assert result["hook_event"] == ""
    assert result["tool_name"] == ""
    assert result["tool_input"] == {}
    assert result["tool_response"] == {}


# ---------------------------------------------------------------------------
# extract_content
# ---------------------------------------------------------------------------

def test_extract_content_write_tool_content():
    hook_input = {
        "hook_event": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/out.py", "content": "SECRET=abc123"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "SECRET=abc123" in content


def test_extract_content_write_tool_file_path():
    hook_input = {
        "hook_event": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/passwd", "content": "data"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "/etc/passwd" in content


def test_extract_content_edit_tool_old_new_string():
    """Edit tool sends old_string and new_string, not content."""
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/tmp/data.txt",
            "old_string": "safe text",
            "new_string": "CPF: 888.640.180-93",
        },
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "888.640.180-93" in content
    assert "safe text" in content


def test_extract_content_bash_command():
    hook_input = {
        "hook_event": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "rm -rf /" in content


def test_extract_content_posttooluse_stdout():
    hook_input = {
        "hook_event": "PostToolUse",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_response": {"stdout": "sensitive output", "stderr": ""},
    }
    content = extract_content(hook_input)
    assert "sensitive output" in content


def test_extract_content_posttooluse_read_file_block():
    """Read tool nests content under tool_response.file.content."""
    hook_input = {
        "hook_event": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/secrets.env"},
        "tool_response": {
            "type": "text",
            "file": {
                "filePath": "/tmp/secrets.env",
                "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        },
    }
    content = extract_content(hook_input)
    assert "AKIAIOSFODNN7EXAMPLE" in content


def test_extract_content_posttooluse_not_included_for_pretooluse():
    """tool_response should NOT be scanned for PreToolUse events."""
    hook_input = {
        "hook_event": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_response": {"stdout": "should_not_appear"},
    }
    content = extract_content(hook_input)
    assert "should_not_appear" not in content


# ---------------------------------------------------------------------------
# format_allow_response
# ---------------------------------------------------------------------------

def test_format_allow_response_pretooluse():
    raw = format_allow_response("PreToolUse")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert data["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_format_allow_response_pretooluse_with_context():
    raw = format_allow_response("PreToolUse", context="All checks passed")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert data["hookSpecificOutput"]["permissionDecisionReason"] == "All checks passed"


def test_format_allow_response_posttooluse_uses_additional_context():
    raw = format_allow_response("PostToolUse", context="scan ok")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert data["hookSpecificOutput"]["additionalContext"] == "scan ok"


def test_format_allow_response_posttooluse_no_permission_decision():
    raw = format_allow_response("PostToolUse")
    data = json.loads(raw)
    assert "permissionDecision" not in data["hookSpecificOutput"]


# ---------------------------------------------------------------------------
# format_deny_response
# ---------------------------------------------------------------------------

def test_format_deny_response_pretooluse():
    raw = format_deny_response("PreToolUse", reason="Secret detected")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert data["hookSpecificOutput"]["permissionDecisionReason"] == "Secret detected"
    assert data["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_format_deny_response_posttooluse():
    raw = format_deny_response("PostToolUse", reason="PII found in output")
    data = json.loads(raw)
    assert data["decision"] == "block"
    assert data["reason"] == "PII found in output"
    assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


# ---------------------------------------------------------------------------
# format_audit_response
# ---------------------------------------------------------------------------

def test_format_audit_response_pretooluse():
    raw = format_audit_response("PreToolUse", context="[AUDIT] Would have blocked: secret")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "[AUDIT]" in data["hookSpecificOutput"]["permissionDecisionReason"]


def test_format_audit_response_posttooluse():
    raw = format_audit_response("PostToolUse", context="[AUDIT] PII detected")
    data = json.loads(raw)
    assert data["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert "[AUDIT]" in data["hookSpecificOutput"]["additionalContext"]


def test_extract_content_prescan_read_pretooluse(tmp_path):
    """PreToolUse + Read should open and scan the actual file."""
    target = tmp_path / "data.txt"
    # CPF split to avoid triggering tatu-hook on this source file itself
    cpf = "928.385." + "640-64"
    target.write_text(f"line1\nCPF: {cpf}\nline3\n")
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert cpf in content
    assert str(target) in content  # file_path still included


def test_extract_content_prescan_resolves_relative_path(tmp_path):
    """Relative file_path should be resolved against cwd."""
    target = tmp_path / "secrets.env"
    target.write_text("API_KEY=sk-ant-secret123\n")
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "secrets.env"},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert "sk-ant-secret123" in content


def test_extract_content_prescan_skip_missing_file(tmp_path):
    """Missing file should skip pre-scan, return only file_path."""
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "nonexistent.txt")},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert "nonexistent.txt" in content
    # Should only contain the file path, nothing else meaningful
    assert content.strip() == str(tmp_path / "nonexistent.txt")


def test_extract_content_prescan_skip_binary_file(tmp_path):
    """Binary file should skip pre-scan, return only file_path."""
    target = tmp_path / "image.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert str(target) in content
    assert "\x89" not in content


def test_extract_content_prescan_skip_large_file(tmp_path):
    """Files over 1MB should skip pre-scan."""
    target = tmp_path / "large.txt"
    target.write_text("A" * (1024 * 1024 + 1))
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert str(target) in content
    assert len(content) < 1024 * 1024  # did not read the large file


def test_extract_content_no_prescan_for_write_pretooluse(tmp_path):
    """Write tool at PreToolUse should NOT read any file from disk."""
    target = tmp_path / "secret.txt"
    target.write_text("TOP SECRET DATA")
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(target), "content": "new content"},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert "TOP SECRET DATA" not in content
    assert "new content" in content


# ---------------------------------------------------------------------------
# Cursor input normalization
# ---------------------------------------------------------------------------

def test_parse_cursor_before_shell_execution():
    """beforeShellExecution normalizes to Bash PreToolUse."""
    raw = json.dumps({
        "hook_event_name": "beforeShellExecution",
        "command": "rm -rf /important",
        "cwd": "/project",
        "session_id": "sess-123",
    })
    result = parse_hook_input(raw)
    assert result["tool_name"] == "Bash"
    assert result["tool_input"] == {"command": "rm -rf /important"}
    assert result["hook_event"] == "PreToolUse"
    assert result["cwd"] == "/project"
    assert result["session_id"] == "sess-123"


def test_extract_content_cursor_shell():
    """Content from normalized beforeShellExecution input."""
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "rm -rf /" in content


def test_parse_cursor_before_read_file():
    """beforeReadFile normalizes to Read PreToolUse."""
    raw = json.dumps({
        "hook_event_name": "beforeReadFile",
        "file_path": "/project/.env",
        "content": "SECRET=abc123",
        "session_id": "sess-456",
    })
    result = parse_hook_input(raw)
    assert result["tool_name"] == "Read"
    assert result["tool_input"]["file_path"] == "/project/.env"
    assert result["tool_input"]["content"] == "SECRET=abc123"
    assert result["hook_event"] == "PreToolUse"


def test_parse_cursor_before_read_file_no_content():
    """beforeReadFile without content field still normalizes."""
    raw = json.dumps({
        "hook_event_name": "beforeReadFile",
        "file_path": "/project/data.txt",
        "session_id": "sess-789",
    })
    result = parse_hook_input(raw)
    assert result["tool_name"] == "Read"
    assert result["tool_input"]["file_path"] == "/project/data.txt"
    assert result["tool_input"].get("content", "") == ""


def test_parse_cursor_pretooluse_normalizes_event_and_tool():
    """Cursor preToolUse with Shell tool normalizes to PreToolUse + Bash."""
    raw = json.dumps({
        "hook_event_name": "preToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "npm install"},
        "cursor_version": "1.0.0",
        "session_id": "sess-100",
        "cwd": "/project",
    })
    result = parse_hook_input(raw)
    assert result["hook_event"] == "PreToolUse"
    assert result["tool_name"] == "Bash"
    assert result["session_id"] == "sess-100"


def test_parse_cursor_posttooluse_with_tool_output_string():
    """Cursor postToolUse sends tool_output as string, not tool_response dict."""
    raw = json.dumps({
        "hook_event_name": "postToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "cat secrets.env"},
        "tool_output": '{"stdout":"SECRET=abc123"}',
        "cursor_version": "1.0.0",
        "session_id": "sess-200",
    })
    result = parse_hook_input(raw)
    assert result["hook_event"] == "PostToolUse"
    assert result["tool_name"] == "Bash"
    assert result["tool_response"]["stdout"] == "SECRET=abc123"


def test_parse_cursor_posttooluse_with_plain_string_output():
    """Cursor postToolUse with non-JSON tool_output wraps as stdout."""
    raw = json.dumps({
        "hook_event_name": "postToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "echo hi"},
        "tool_output": "plain text output",
        "cursor_version": "1.0.0",
    })
    result = parse_hook_input(raw)
    assert result["tool_response"] == {"stdout": "plain text output"}


def test_extract_content_cursor_read_with_inline_content():
    """beforeReadFile with content should scan the inline content."""
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/project/.env", "content": "DB_PASSWORD=secret"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "DB_PASSWORD=secret" in content
