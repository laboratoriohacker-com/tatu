# Auto-register Hooks in `tatu-hook init`

**Date:** 2026-03-17
**Status:** Draft

## Problem

After running `tatu-hook init`, users must manually edit `.claude/settings.json` to add hook entries. This is error-prone and undiscoverable.

## Solution

The `init` command automatically registers tatu-hook in the Claude Code settings file after syncing rules. A `--scope` flag controls whether hooks are registered globally (`~/.claude/settings.json`) or per-project (`.claude/settings.json`). A `--no-register` flag skips hook registration for users who manage their settings externally.

## Design

### New CLI arguments

Add to the `init` subparser:
```
--scope {global,project}  (default: global)
--no-register             Skip hook registration in Claude Code settings
```

- `global`: `os.path.expanduser("~/.claude/settings.json")`
- `project`: `.claude/settings.json` relative to cwd

### Hook entries

Three entries are registered, matching the existing README documentation:

```json
{
  "SessionStart": [
    { "hooks": [{ "type": "command", "command": "tatu-hook run --event session-start" }] }
  ],
  "PreToolUse": [
    { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook run --event pre" }] }
  ],
  "PostToolUse": [
    { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook run --event post" }] }
  ]
}
```

### Merge logic (`_register_hooks` function)

1. Resolve settings file path from `--scope` using `os.path.expanduser` for global scope
2. Create parent directory if needed (`~/.claude/` or `.claude/`)
3. Read existing file as JSON, or start with `{}` if missing
4. Ensure `settings["hooks"]` exists as a dict
5. For each of the 3 hook events (`SessionStart`, `PreToolUse`, `PostToolUse`):
   - Get or create the event array: `settings["hooks"][event_name]`
   - Check if already registered (see dedup logic below)
   - If found: skip (already registered)
   - If not found: append the entry
6. Write the file back with `json.dump(indent=2)`
7. Return `(path, was_modified)` for output messaging

### Dedup check

The settings structure nests hooks two levels deep. Each event array contains entry objects, each with a `"hooks"` array of hook objects. The dedup traversal:

```python
def _has_tatu_hook(entries: list) -> bool:
    for entry in entries:
        for hook_obj in entry.get("hooks", []):
            if "tatu-hook run" in hook_obj.get("command", ""):
                return True
    return False
```

An entry is considered "already registered" if any hook object at this nested level has a `command` string containing `"tatu-hook run"`. This is intentionally broad — if the user has `tatu-hook run --event pre --tatu-dir /custom`, it still counts as registered.

### Output

```
Initialized tatu-hook. Synced 46 rule(s).
Registered hooks in ~/.claude/settings.json
```

Or if already present:
```
Initialized tatu-hook. Synced 46 rule(s).
Hooks already registered in ~/.claude/settings.json
```

Or with `--no-register`:
```
Initialized tatu-hook. Synced 46 rule(s).
```

### Error handling

- If the settings file contains invalid JSON: print a warning, skip hook registration (don't corrupt the file), continue with init
- If the directory can't be created (permissions): print a warning, skip
- If `HOME` is unset and scope is `global`: `os.path.expanduser` returns `~/.claude/settings.json` unchanged — the subsequent file operations will fail and the warning path handles it

### Files changed

| File | Change |
|------|--------|
| `tatu-hook/src/tatu_hook/cli.py` | Add `--scope` and `--no-register` args, `_register_hooks()` function, call from init |
| `tatu-hook/tests/test_cli.py` | Tests for hook registration |
| `tatu-hook/README.md` | Simplify Quick Start section |

### Test plan

1. **Unit: register hooks in empty settings file** — creates file with all 3 hook entries
2. **Unit: register hooks in existing settings** — preserves other settings, adds hooks
3. **Unit: dedup — skip if already registered** — no duplicate entries on re-run
4. **Unit: project scope** — writes to `.claude/settings.json` relative to cwd
5. **Unit: invalid JSON** — prints warning, doesn't crash, skips registration
6. **Unit: creates parent directory** — `.claude/` created if missing
7. **Unit: --no-register** — skips hook registration entirely
