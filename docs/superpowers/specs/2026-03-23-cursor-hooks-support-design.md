# Cursor Hooks Support for tatu-hook

**Date:** 2026-03-23
**Status:** Approved

## Overview

Add Cursor IDE as a supported platform in `tatu-hook`, allowing the same rule engine and security policies to protect both Claude Code and Cursor users. The `--platform` flag on `tatu-hook init` controls which IDE's hook config gets written.

## Motivation

Cursor is a popular AI-powered IDE that supports a hooks system similar to Claude Code. By adding Cursor support, tatu-hook can provide DevSecOps coverage for teams using either tool — without duplicating rules or infrastructure.

## Key Differences: Claude Code vs Cursor

| Aspect | Claude Code | Cursor |
|--------|------------|--------|
| Config file (global) | `~/.claude/settings.json` | `~/.cursor/hooks.json` |
| Config file (project) | `.claude/settings.json` | `.cursor/hooks.json` |
| Config format | `{"hooks": {"PreToolUse": [...]}}` | `{"version": 1, "hooks": {"preToolUse": [...]}}` |
| Event names | PascalCase (`PreToolUse`) | camelCase (`preToolUse`) |
| Env vars | `CLAUDE_PROJECT_DIR` | `CURSOR_PROJECT_DIR` (also aliases `CLAUDE_PROJECT_DIR`) |
| Exit codes | 0=allow, 2=deny | 0=success, 2=block |
| Extra events | — | `beforeShellExecution`, `beforeReadFile`, others |

## Design

### 1. Platform Abstraction

Introduce a `platform.py` module in `tatu-hook` that encapsulates IDE-specific differences:

- **Event name mapping**: Translate between Cursor camelCase (`preToolUse`) and internal PascalCase (`PreToolUse`)
- **Config file paths**: Per-platform, per-scope (global/project)
- **Config format**: Cursor uses `{"version": 1, "hooks": {...}}` with `command`/`type`/`timeout` entry fields
- **Input parsing**: Detect platform from env vars or input JSON shape, normalize to internal format
- **Output formatting**: Format responses per platform expectations

### 2. Hook Registration

`tatu-hook init --platform cursor` writes to Cursor's `hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {"command": "tatu-hook run --event session-start", "type": "command"}
    ],
    "preToolUse": [
      {"command": "tatu-hook run --event pre", "type": "command"}
    ],
    "postToolUse": [
      {"command": "tatu-hook run --event post", "type": "command"}
    ],
    "beforeShellExecution": [
      {"command": "tatu-hook run --event pre-shell", "type": "command"}
    ],
    "beforeReadFile": [
      {"command": "tatu-hook run --event pre-read", "type": "command"}
    ]
  }
}
```

`--scope global` writes to `~/.cursor/hooks.json`, `--scope project` writes to `.cursor/hooks.json`.

### 3. New CLI Events

Two new `--event` values for Cursor-specific hooks:

- **`pre-shell`** — Parses `beforeShellExecution` input, extracts the shell command, evaluates against rules with event=`PreToolUse` and tool=`Bash`. This gives granular interception of shell commands before execution.
- **`pre-read`** — Parses `beforeReadFile` input, extracts the file path, pre-scans the file content, evaluates against rules with event=`PreToolUse` and tool=`Read`. Catches secrets/PII in files before Cursor reads them.

Both map to existing rule event/matcher combinations — no rule schema changes needed.

### 4. Cursor Wire Protocol (Input/Output JSON)

#### 4.1 `sessionStart`

**Input (stdin):**
```json
{
  "conversation_id": "string",
  "hook_event_name": "sessionStart",
  "cursor_version": "string",
  "workspace_roots": ["/project"],
  "user_email": "user@example.com",
  "session_id": "unique-session-id"
}
```

**Output (stdout):**
```json
{
  "additional_context": "Synced 46 rule(s)."
}
```

**Mapping:** `session_id` from input directly. `cwd` from `workspace_roots[0]`.

#### 4.2 `preToolUse`

**Input (stdin):**
```json
{
  "hook_event_name": "preToolUse",
  "tool_name": "Shell",
  "tool_input": {"command": "npm install", "working_directory": "/project"},
  "tool_use_id": "abc123",
  "cwd": "/project",
  "session_id": "unique-session-id"
}
```

**Output — allow:**
```json
{
  "permission": "allow"
}
```

**Output — deny:**
```json
{
  "permission": "deny",
  "user_message": "[BLOCKED] Destructive command detected",
  "agent_message": "Rule 'rm-rf-protection' blocked this action."
}
```

**Mapping:** `tool_name` and `tool_input` map directly to internal format. Cursor uses `"Shell"` where Claude Code uses `"Bash"` — normalize in platform layer.

#### 4.3 `postToolUse`

**Input (stdin):**
```json
{
  "hook_event_name": "postToolUse",
  "tool_name": "Shell",
  "tool_input": {"command": "cat secrets.env"},
  "tool_output": "{\"stdout\":\"AWS_SECRET=AKIA...\"}",
  "cwd": "/project",
  "session_id": "unique-session-id"
}
```

**Output:**
```json
{
  "additional_context": "[ALERT] AWS key detected in command output."
}
```

**Mapping:** `tool_output` (string) maps to `tool_response`. Parse as JSON if possible, extract `stdout`/`stderr`.

#### 4.4 `beforeShellExecution`

**Input (stdin):**
```json
{
  "hook_event_name": "beforeShellExecution",
  "command": "rm -rf /",
  "cwd": "/project",
  "sandbox": false,
  "session_id": "unique-session-id"
}
```

**Output — allow:**
```json
{
  "permission": "allow"
}
```

**Output — deny:**
```json
{
  "permission": "deny",
  "user_message": "[BLOCKED] Destructive command: rm -rf",
  "agent_message": "Rule 'rm-rf-protection' blocked this shell command."
}
```

**Content extraction:** The `command` field is the full shell command string. Wrap as `tool_input = {"command": command}` and set `tool_name = "Bash"` for rule evaluation.

#### 4.5 `beforeReadFile`

**Input (stdin):**
```json
{
  "hook_event_name": "beforeReadFile",
  "file_path": "/project/.env",
  "content": "AWS_SECRET_KEY=AKIA...",
  "session_id": "unique-session-id"
}
```

**Output — allow:**
```json
{
  "permission": "allow"
}
```

**Output — deny:**
```json
{
  "permission": "deny",
  "user_message": "[BLOCKED] Secrets detected in file."
}
```

**Content extraction:** If `content` is provided, scan it directly. Otherwise, pre-scan the file from disk (reuse existing file pre-scan logic from `extract_content`). Set `tool_name = "Read"` and `tool_input = {"file_path": file_path}` for rule evaluation.

### 5. Platform Detection

**Auto-detect platform** from the input JSON:
- If `cursor_version` field is present → Cursor
- If `hook_event_name` uses camelCase (`preToolUse`) → Cursor
- Otherwise → Claude Code

This is used by `run_hook()` to select the correct output formatter. The `--event` flag already determines input parsing (e.g., `pre-shell` is always Cursor).

**Session ID resolution:**
- Claude Code: `CLAUDE_SESSION_ID` env var or `session_id` from input JSON
- Cursor: `session_id` from input JSON (always present), or `conversation_id` as fallback

### 6. Architecture: `run_hook()` / `main()` Responsibility Split

`run_hook()` remains **platform-agnostic**. It receives a normalized `HookInput` and returns a `(decision, context)` tuple. The `main()` function in `cli.py` owns:

1. **Before `run_hook()`**: Parse raw stdin JSON using platform-specific parser → produce normalized `HookInput`
2. **Call `run_hook()`**: Engine evaluation, event reporting (adds `platform` to metadata)
3. **After `run_hook()`**: Format `(decision, context)` into platform-specific JSON output and set exit code

This keeps the engine and core logic completely platform-unaware.

### 7. Event Reporting

No backend changes required. The reporter already sends `hook_event`, `tool_name`, and `metadata`. Add a `platform` field to event metadata (`"cursor"` or `"claude_code"`) so the dashboard can distinguish event sources.

### 8. CLI Changes (`cli.py`)

- Add `--platform` option to `tatu-hook init` (choices: `claude`, `cursor`; default: `claude`)
- Add `pre-shell` and `pre-read` to `--event` choices in `tatu-hook run`
- Refactor `register_hooks()` to use platform abstraction for config path resolution and config format generation
- Refactor `_has_tatu_hook()` to handle both config structures (Claude Code nests under `hooks[event][].command`, Cursor uses same structure but different top-level format with `version` key)

### 9. Backwards Compatibility

- Running `tatu-hook init` (no `--platform` flag) behaves exactly as today (Claude Code)
- Running `tatu-hook init --platform cursor` is independent — it writes to `~/.cursor/hooks.json`, not touching `~/.claude/settings.json`
- Users can run both `tatu-hook init` and `tatu-hook init --platform cursor` to register in both IDEs simultaneously
- The `tatu-hook run` command auto-detects platform from input JSON, so the same binary serves both

### 10. Scope of Changes

**Modified files:**
- `tatu-hook/src/tatu_hook/cli.py` — `--platform` flag on init, new event handlers, platform-aware registration
- `tatu-hook/src/tatu_hook/protocol.py` — Platform detection, Cursor input normalization, Cursor output formatting

**New files:**
- `tatu-hook/src/tatu_hook/platform.py` — Platform abstraction (config paths, event mapping, hook entry format)

**Unchanged:**
- `engine.py` — Rule evaluation logic unchanged
- `sync.py` — Rule sync unchanged
- `reporter.py` — Only adds `platform` to metadata dict (trivial)
- All 46 rule YAML files — Work as-is
- Backend API — No changes needed
- Frontend — No changes needed

### 11. Tool Name Mapping

Cursor uses different tool names than Claude Code in some cases:

| Cursor | Internal (Claude Code) |
|--------|----------------------|
| `Shell` | `Bash` |
| `Read` | `Read` |
| `Write` | `Write` |
| `Edit` | `Edit` |

The platform layer normalizes `Shell` → `Bash` on input so rules with `matcher: Bash` work for both platforms.

## Testing

**Happy path:**
- Unit tests for platform detection (`cursor_version` field, camelCase events)
- Unit tests for Cursor input normalization (all 5 event types)
- Unit tests for Cursor output formatting (allow and deny for each event)
- Unit tests for hook registration config generation (global and project scope)
- Unit tests for tool name mapping (`Shell` → `Bash`)
- Integration test: `tatu-hook init --platform cursor` writes correct `hooks.json`

**Error/edge cases:**
- Malformed Cursor JSON input (missing fields, invalid JSON) — should fail-open (exit 0)
- Unrecognized event type from Cursor — should fail-open (exit 0)
- `beforeReadFile` with no `content` field — should fall back to disk pre-scan
- Rules that match on `pre-shell` event (destructive command rules like `rm-rf-protection`)
- Rules that match on `pre-read` event (secrets/PII rules scanning file content)
