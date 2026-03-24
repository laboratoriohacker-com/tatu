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

### 4. Protocol Changes (`protocol.py`)

Update input parsing to:

1. **Auto-detect platform** from input JSON shape. Cursor sends `hook_event_name` field; Claude Code sends `tool_name` at top level.
2. **Normalize** Cursor input fields to the internal `HookInput` format that the engine expects (`tool_name`, `tool_input`, `tool_response`, `session_id`, `cwd`).
3. **Format output** according to detected platform. Cursor expects different response structures than Claude Code (e.g., for `preToolUse`, Cursor uses `permissionDecision`/`permissionDecisionReason` in `hookSpecificOutput`; for `beforeShellExecution`, it uses a different output shape).

### 5. Event Reporting

No backend changes required. The reporter already sends `hook_event`, `tool_name`, and `metadata`. Add a `platform` field to event metadata (`"cursor"` or `"claude_code"`) so the dashboard can distinguish event sources.

### 6. CLI Changes (`cli.py`)

- Add `--platform` option to `tatu-hook init` (choices: `claude`, `cursor`; default: `claude`)
- Add `pre-shell` and `pre-read` to `--event` choices in `tatu-hook run`
- Platform detection in `run_hook()` to normalize input/output per platform

### 7. Scope of Changes

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

## Testing

- Unit tests for platform detection (env var and JSON shape)
- Unit tests for Cursor input normalization (all 5 event types)
- Unit tests for Cursor output formatting
- Unit tests for hook registration config generation
- Integration test: `tatu-hook init --platform cursor` writes correct `hooks.json`
