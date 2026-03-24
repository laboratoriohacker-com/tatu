# Cursor Hooks Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cursor IDE hook support to tatu-hook so the same security rules engine protects both Claude Code and Cursor users.

**Architecture:** Introduce a `platform.py` module encapsulating all IDE-specific differences (config paths, event names, input/output JSON shapes, tool name mapping). The existing `run_hook()` stays platform-agnostic — `main()` in `cli.py` handles platform-specific parsing before and formatting after. Two new CLI events (`pre-shell`, `pre-read`) handle Cursor-specific hooks by mapping to existing rule event/tool combinations.

**Tech Stack:** Python 3.11+, pytest, JSON, no new dependencies

**Spec:** `docs/superpowers/specs/2026-03-23-cursor-hooks-support-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `tatu-hook/src/tatu_hook/platform.py` | Create | Platform abstraction: config paths, event mapping, tool name normalization, hook entry generation, input normalization, output formatting |
| `tatu-hook/tests/test_platform.py` | Create | Tests for all platform abstraction logic |
| `tatu-hook/src/tatu_hook/cli.py` | Modify | Add `--platform` flag to init, new events to run, use platform module for registration and I/O |
| `tatu-hook/tests/test_cli.py` | Modify | Add Cursor-specific tests for init registration, pre-shell, pre-read events |
| `tatu-hook/src/tatu_hook/protocol.py` | Modify | Add Cursor input normalization helpers for beforeShellExecution and beforeReadFile |
| `tatu-hook/tests/test_protocol.py` | Modify | Add tests for Cursor input parsing and content extraction |

---

### Task 1: Platform abstraction module — config paths and constants

**Files:**
- Create: `tatu-hook/src/tatu_hook/platform.py`
- Create: `tatu-hook/tests/test_platform.py`

- [ ] **Step 1: Write failing tests for platform config paths**

```python
# tatu-hook/tests/test_platform.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v"`
Expected: FAIL — `ModuleNotFoundError: No module named 'tatu_hook.platform'`

- [ ] **Step 3: Implement platform config paths**

```python
# tatu-hook/src/tatu_hook/platform.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/platform.py tatu-hook/tests/test_platform.py
git commit -m "feat: add platform abstraction module with config paths"
```

---

### Task 2: Platform abstraction — hook entry generation and registration helpers

**Files:**
- Modify: `tatu-hook/src/tatu_hook/platform.py`
- Modify: `tatu-hook/tests/test_platform.py`

- [ ] **Step 1: Write failing tests for hook entries and detection**

Append to `tatu-hook/tests/test_platform.py`:

```python
from tatu_hook.platform import get_hook_entries, has_tatu_hook


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v"`
Expected: FAIL — `ImportError: cannot import name 'get_hook_entries'`

- [ ] **Step 3: Implement hook entries and detection**

Add to `tatu-hook/src/tatu_hook/platform.py`:

```python
# Claude Code hook entries (existing format)
_CLAUDE_HOOK_ENTRIES = {
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
_CURSOR_HOOK_ENTRIES = {
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/platform.py tatu-hook/tests/test_platform.py
git commit -m "feat: add hook entry generation and detection for claude/cursor"
```

---

### Task 3: Platform abstraction — input normalization and output formatting

**Files:**
- Modify: `tatu-hook/src/tatu_hook/platform.py`
- Modify: `tatu-hook/tests/test_platform.py`

- [ ] **Step 1: Write failing tests for platform detection**

Append to `tatu-hook/tests/test_platform.py`:

```python
import json

from tatu_hook.platform import detect_platform


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
```

- [ ] **Step 2: Write failing tests for Cursor output formatting**

Append to `tatu-hook/tests/test_platform.py`:

```python
from tatu_hook.platform import format_cursor_allow, format_cursor_deny


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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v -k 'detect or format_cursor'"`
Expected: FAIL — `ImportError`

- [ ] **Step 4: Implement detection and Cursor output formatting**

Add to `tatu-hook/src/tatu_hook/platform.py`:

```python
import json

# Cursor events that use camelCase (first char lowercase)
_CURSOR_EVENTS = {
    "sessionStart", "preToolUse", "postToolUse",
    "beforeShellExecution", "afterShellExecution",
    "beforeReadFile", "afterFileEdit",
    "beforeMCPExecution", "afterMCPExecution",
    "subagentStart", "subagentStop",
    "beforeSubmitPrompt", "preCompact",
    "afterAgentResponse", "afterAgentThought",
    "stop",
}


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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_platform.py -v"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tatu-hook/src/tatu_hook/platform.py tatu-hook/tests/test_platform.py
git commit -m "feat: add platform detection and Cursor output formatting"
```

---

### Task 4: Protocol — Cursor input normalization for beforeShellExecution and beforeReadFile

**Files:**
- Modify: `tatu-hook/src/tatu_hook/protocol.py`
- Modify: `tatu-hook/tests/test_protocol.py`

- [ ] **Step 1: Write failing tests for Cursor shell input normalization**

Append to `tatu-hook/tests/test_protocol.py`:

```python
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
```

- [ ] **Step 2: Write failing tests for Cursor read input normalization**

Append to `tatu-hook/tests/test_protocol.py`:

```python
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


def test_extract_content_cursor_read_with_inline_content():
    """beforeReadFile with content should scan the inline content."""
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/project/.env", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
        "tool_response": {},
    }
    content = extract_content(hook_input)
    assert "AKIAIOSFODNN7EXAMPLE" in content
```

- [ ] **Step 2b: Write failing tests for standard Cursor preToolUse/postToolUse normalization**

Append to `tatu-hook/tests/test_protocol.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_protocol.py -v -k 'cursor'"`
Expected: FAIL — tests expecting normalization that doesn't exist yet

- [ ] **Step 4: Update `parse_hook_input` to normalize Cursor-specific events**

In `tatu-hook/src/tatu_hook/protocol.py`, update `parse_hook_input`:

```python
def parse_hook_input(raw: str) -> dict:
    data = json.loads(raw)
    _debug_log(f"RAW INPUT: {json.dumps(data, indent=2, default=str)[:2000]}")

    event = data.get("hook_event_name", "")

    # Normalize Cursor-specific events to internal format
    if event == "beforeShellExecution":
        return {
            "hook_event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": data.get("command", "")},
            "tool_response": {},
            "session_id": data.get("session_id", data.get("conversation_id", "")),
            "cwd": data.get("cwd", ""),
            "raw": data,
        }

    if event == "beforeReadFile":
        tool_input = {"file_path": data.get("file_path", "")}
        content = data.get("content", "")
        if content:
            tool_input["content"] = content
        return {
            "hook_event": "PreToolUse",
            "tool_name": "Read",
            "tool_input": tool_input,
            "tool_response": {},
            "session_id": data.get("session_id", data.get("conversation_id", "")),
            "cwd": data.get("cwd", ""),
            "raw": data,
        }

    # Normalize Cursor tool names
    tool_name = data.get("tool_name", "")
    if tool_name == "Shell":
        tool_name = "Bash"

    # Normalize Cursor camelCase events to PascalCase
    event_map = {"preToolUse": "PreToolUse", "postToolUse": "PostToolUse", "sessionStart": "SessionStart"}
    hook_event = event_map.get(event, event)

    # Cursor postToolUse sends tool_output as a string, not tool_response dict
    tool_response = data.get("tool_response", {})
    if not tool_response and "tool_output" in data:
        raw_output = data["tool_output"]
        if isinstance(raw_output, str):
            try:
                tool_response = json.loads(raw_output)
            except (json.JSONDecodeError, TypeError):
                tool_response = {"stdout": raw_output}
        elif isinstance(raw_output, dict):
            tool_response = raw_output

    return {
        "hook_event": hook_event,
        "tool_name": tool_name,
        "tool_input": data.get("tool_input", {}),
        "tool_response": tool_response,
        "session_id": data.get("session_id", data.get("conversation_id", "")),
        "cwd": data.get("cwd", ""),
        "raw": data,
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_protocol.py -v"`
Expected: ALL PASS (new and existing)

- [ ] **Step 6: Commit**

```bash
git add tatu-hook/src/tatu_hook/protocol.py tatu-hook/tests/test_protocol.py
git commit -m "feat: normalize Cursor hook input in protocol parser"
```

---

### Task 5: CLI — Add `--platform` flag to init and Cursor registration

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`
- Modify: `tatu-hook/tests/test_cli.py`

- [ ] **Step 1: Write failing tests for Cursor hook registration**

Append to `tatu-hook/tests/test_cli.py`:

```python
from tatu_hook.cli import register_hooks_cursor


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_cli.py::TestRegisterHooksCursor -v"`
Expected: FAIL — `ImportError: cannot import name 'register_hooks_cursor'`

- [ ] **Step 3: Implement `register_hooks_cursor` and update `register_hooks` to use platform module**

In `tatu-hook/src/tatu_hook/cli.py`:

1. Add imports at top:
```python
from tatu_hook.platform import (
    resolve_config_path,
    get_hook_entries,
    has_tatu_hook as platform_has_tatu_hook,
    detect_platform,
    format_cursor_allow,
    format_cursor_deny,
)
```

2. Add `register_hooks_cursor` function:
```python
def register_hooks_cursor(scope: str = "global") -> tuple[str, bool]:
    """Register tatu-hook in Cursor hooks.json.

    Returns (config_path, was_modified).
    """
    config_path = resolve_config_path("cursor", scope)
    parent = os.path.dirname(config_path)
    os.makedirs(parent, exist_ok=True)

    config = {"version": 1, "hooks": {}}
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        if "hooks" not in config:
            config["hooks"] = {}

    entries = get_hook_entries("cursor")
    modified = False
    for event_name, event_entries in entries.items():
        if event_name not in config["hooks"]:
            config["hooks"][event_name] = []
        if not platform_has_tatu_hook("cursor", config["hooks"][event_name]):
            config["hooks"][event_name].extend(event_entries)
            modified = True

    if modified:
        config["version"] = 1
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")

    return config_path, modified
```

3. Update `build_parser` to add `--platform` to init:
```python
init_parser.add_argument("--platform", choices=["claude", "cursor"], default="claude",
                         help="Target platform (default: claude)")
```

4. Update `build_parser` to add new events to run:
```python
run_parser.add_argument(
    "--event", choices=["session-start", "pre", "post", "pre-shell", "pre-read"],
    required=True,
)
```

5. Update init handler in `main()` to use platform:
```python
if not args.no_register:
    try:
        if args.platform == "cursor":
            path, modified = register_hooks_cursor(args.scope)
        else:
            path, modified = register_hooks(args.scope)
        ...
```

- [ ] **Step 4: Run all tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_cli.py -v"`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py tatu-hook/tests/test_cli.py
git commit -m "feat: add --platform cursor flag and Cursor hook registration"
```

---

### Task 6: CLI — Handle new events (pre-shell, pre-read) and Cursor output formatting

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`
- Modify: `tatu-hook/tests/test_cli.py`

- [ ] **Step 1: Write failing tests for pre-shell event**

Append to `tatu-hook/tests/test_cli.py`:

```python
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
        assert "rm" in result["context"].lower() or "Destructive" in result["context"]

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
```

- [ ] **Step 2: Write failing tests for pre-read event**

Append to `tatu-hook/tests/test_cli.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_cli.py -v -k 'PreShell or PreRead'"`
Expected: FAIL — `run_hook` doesn't handle `pre-shell` or `pre-read` events

- [ ] **Step 4: Update `run_hook` to handle new events**

In `tatu-hook/src/tatu_hook/cli.py`, update `run_hook`:

```python
def run_hook(event: str, raw_input: str, tatu_dir: str | None = None) -> dict:
    """Core hook execution pipeline."""
    manifest = load_manifest(tatu_dir)
    raw_rules = load_rules_from_cache(tatu_dir)
    rules = load_yaml_rules(raw_rules)

    hook_input = parse_hook_input(raw_input)
    content = extract_content(hook_input)

    tool_name = hook_input.get("tool_name", "")

    # Map CLI event to internal hook event name
    _event_to_hook = {
        "pre": "PreToolUse",
        "post": "PostToolUse",
        "pre-shell": "PreToolUse",
        "pre-read": "PreToolUse",
    }
    hook_event_name = _event_to_hook.get(event, "PreToolUse")

    results = evaluate_rules(rules, tool_name, content, hook_event_name)

    # ... rest unchanged ...
```

- [ ] **Step 5: Update `main()` to handle new events and Cursor output formatting**

In `tatu-hook/src/tatu_hook/cli.py`, update the run handler in `main()`:

```python
    if args.command == "run":
        tatu_dir = args.tatu_dir
        event = args.event

        # Map to Cursor event names for output formatting
        _event_to_cursor = {
            "pre": "preToolUse",
            "post": "postToolUse",
            "pre-shell": "beforeShellExecution",
            "pre-read": "beforeReadFile",
            "session-start": "sessionStart",
        }

        if event == "session-start":
            rules = sync_rules(tatu_dir)
            msg = f"Synced {len(rules)} rule(s)."
            # Read stdin to detect platform (Cursor sends JSON on sessionStart)
            raw_input = sys.stdin.read().strip()
            platform = "claude"
            if raw_input:
                try:
                    input_data = json.loads(raw_input)
                    platform = detect_platform(input_data)
                except (json.JSONDecodeError, TypeError):
                    pass
            if platform == "cursor":
                response = format_cursor_allow("sessionStart", msg)
            else:
                response = format_allow_response("SessionStart", msg)
            sys.stdout.write(response + "\n")
            sys.exit(0)

        raw_input = sys.stdin.read()

        # Detect platform for output formatting
        try:
            input_data = json.loads(raw_input)
            platform = detect_platform(input_data)
        except (json.JSONDecodeError, TypeError):
            platform = "claude"

        # Map event to internal hook event name for Claude output
        _event_to_hook = {
            "pre": "PreToolUse",
            "post": "PostToolUse",
            "pre-shell": "PreToolUse",
            "pre-read": "PreToolUse",
        }
        hook_event_name = _event_to_hook.get(event, "PreToolUse")

        # Fail-open: any unhandled error results in allow + exit 0
        try:
            result = run_hook(event, raw_input, tatu_dir)
        except Exception:
            sys.stdout.write("{}\n")
            sys.exit(0)

        if platform == "cursor":
            cursor_event = _event_to_cursor.get(event, "preToolUse")
            if result["decision"] == "deny":
                response = format_cursor_deny(cursor_event, result["context"] or "Blocked by policy")
                sys.stderr.write(response + "\n")
                flush_reports()
                sys.exit(2)
            else:
                response = format_cursor_allow(cursor_event, result["context"])
                sys.stdout.write(response + "\n")
                flush_reports()
                sys.exit(0)
        else:
            if result["decision"] == "deny":
                response = format_deny_response(hook_event_name, result["context"] or "Blocked by policy")
                sys.stderr.write(response + "\n")
                flush_reports()
                sys.exit(2)
            else:
                response = format_allow_response(hook_event_name, result["context"])
                sys.stdout.write(response + "\n")
                flush_reports()
                sys.exit(0)
```

- [ ] **Step 6: Run all tests**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/ -v"`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py tatu-hook/tests/test_cli.py
git commit -m "feat: handle pre-shell/pre-read events and Cursor output formatting"
```

---

### Task 7: Add platform metadata to event reporting

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`

- [ ] **Step 1: Write failing test**

Append to `tatu-hook/tests/test_cli.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/test_cli.py::TestEventReportingPlatform -v"`
Expected: FAIL — metadata does not contain `platform` key

- [ ] **Step 3: Add platform detection to `run_hook` and include in metadata**

In `tatu-hook/src/tatu_hook/cli.py`, update `run_hook` to detect platform from input and add to metadata:

```python
def run_hook(event: str, raw_input: str, tatu_dir: str | None = None) -> dict:
    # ... existing code ...
    hook_input = parse_hook_input(raw_input)

    # Detect platform from raw input
    raw_data = hook_input.get("raw", {})
    platform = detect_platform(raw_data)

    # ... existing evaluation code ...

    for match in results:
        report_event(api_url, api_key, {
            # ... existing fields ...
            "metadata": {
                "rule_id": match["rule_id"],
                "category": match["category"],
                "matched_text": match.get("matched", ""),
                "matched_lines": match.get("matched_lines", []),
                "file_path": file_path,
                "platform": platform,
            },
        })
    # ...
```

- [ ] **Step 4: Run all tests**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/ -v"`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py tatu-hook/tests/test_cli.py
git commit -m "feat: include platform in event metadata for dashboard filtering"
```

---

### Task 8: Clean up — remove duplicated code from cli.py, lint, final test run

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`

- [ ] **Step 1: Remove old `_HOOK_ENTRIES`, `_has_tatu_hook`, `_resolve_settings_path` from cli.py**

These are now in `platform.py`. Update `register_hooks` in `cli.py` to use the platform module:

```python
def register_hooks(scope: str = "global") -> tuple[str, bool]:
    """Register tatu-hook in Claude Code settings.json."""
    settings_path = resolve_config_path("claude", scope)
    parent = os.path.dirname(settings_path)
    os.makedirs(parent, exist_ok=True)

    settings = {}
    if os.path.exists(settings_path):
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)

    if "hooks" not in settings:
        settings["hooks"] = {}

    entries = get_hook_entries("claude")
    modified = False
    for event_name, entry in entries.items():
        if event_name not in settings["hooks"]:
            settings["hooks"][event_name] = []
        if not platform_has_tatu_hook("claude", settings["hooks"][event_name]):
            settings["hooks"][event_name].append(entry)
            modified = True

    if modified:
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")

    return settings_path, modified
```

- [ ] **Step 1b: Update `main()` error handler to use `resolve_config_path` instead of removed `_resolve_settings_path`**

In `tatu-hook/src/tatu_hook/cli.py`, in the init handler's error path, replace:
```python
print(f"Warning: Could not parse {_resolve_settings_path(args.scope)} — skipping hook registration.", file=sys.stderr)
```
with:
```python
print(f"Warning: Could not parse config — skipping hook registration.", file=sys.stderr)
```

Also remove the unused `format_audit_response` import from `protocol.py` if it was imported.

- [ ] **Step 2: Update test imports if needed**

In `tatu-hook/tests/test_cli.py`, update imports for `_has_tatu_hook` tests to use platform module:

```python
from tatu_hook.platform import has_tatu_hook as _has_tatu_hook
```

Note: Keep backward compatibility — the `TestHasTatuHook` class should pass using the platform module's function with `"claude"` as the platform argument. Update the test calls:

```python
class TestHasTatuHook:
    def test_detects_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "tatu-hook run --event pre"}]}
        ]
        assert _has_tatu_hook("claude", entries) is True

    def test_no_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "other-hook"}]}
        ]
        assert _has_tatu_hook("claude", entries) is False

    def test_empty_entries(self):
        assert _has_tatu_hook("claude", []) is False

    def test_detects_custom_tatu_hook(self):
        entries = [
            {"hooks": [{"type": "command", "command": "tatu-hook run --event pre --tatu-dir /custom"}]}
        ]
        assert _has_tatu_hook("claude", entries) is True
```

- [ ] **Step 3: Lint all changed files**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && python -m flake8 src/tatu_hook/ tests/ --max-line-length=120"`

- [ ] **Step 4: Run full test suite**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/ -v"`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py tatu-hook/tests/test_cli.py
git commit -m "refactor: migrate hook registration to platform module, remove duplication"
```

---

### Task 9: Update init help text and description

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py`

- [ ] **Step 1: Update parser description and help text**

```python
p = argparse.ArgumentParser(
    description=f"Tatu Hook v{__version__} — security hook for Claude Code and Cursor"
)
# ...
init_parser.add_argument("--no-register", action="store_true",
                         help="Skip hook registration in IDE settings")
```

- [ ] **Step 2: Run full test suite one final time**

Run: `docker compose run --rm backend bash -c "cd /app/../tatu-hook && pip install -e '.[test]' && pytest tests/ -v"`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py
git commit -m "docs: update CLI help text for multi-platform support"
```
