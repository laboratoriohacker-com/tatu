# Read Pre-Scan: Block Sensitive Content Before Claude Reads Files

**Date:** 2026-03-16
**Status:** Draft

## Problem

When Claude Code reads a file containing sensitive content (PII, secrets), the current hook architecture only detects this at PostToolUse — after the file has been read into Claude's context and transmitted to Anthropic's servers. The "block" at PostToolUse is cosmetic: Claude already has the data and can summarize it, including sensitive values like CPF numbers.

This is a compliance (LGPD) and practical risk concern. Data that reaches Anthropic's API cannot be recalled.

## Solution

At PreToolUse for `Read` operations, the hook opens and scans the file itself before Claude reads it. If sensitive content is detected, the hook denies the read entirely. Claude never sees the file content.

The deny reason includes line numbers so the developer knows where the sensitive content is and can provide a redacted version.

## Design

### 1. Pre-scan in `extract_content()` (protocol.py)

When `hook_event == "PreToolUse"` and `tool_name == "Read"` and a `file_path` is present in `tool_input`:

1. Resolve `file_path` against `hook_input["cwd"]` if it is not absolute
2. Attempt to open and read the file as UTF-8
3. If the file doesn't exist, is binary (UnicodeDecodeError), is unreadable (PermissionError), or exceeds 1MB — skip pre-scan, return only the file path (allow the read; Claude Code handles its own errors)
4. If readable — append the file content to the scannable parts list, in addition to the file path (which continues to be included so path-based rules still work)

The 1MB limit exists to keep the synchronous hook fast (<100ms). Files over 1MB that contain sensitive data are a known gap — a future improvement could scan the first 1MB rather than skipping entirely.

The core pre-scan works without changes to the engine or CLI — they already evaluate whatever `extract_content()` returns. Any rule whose matcher includes `Read` and whose events include `PreToolUse` will automatically benefit from pre-scanning. Sections 2 and 3 below are enhancements for better reporting.

### 2. Line numbers in match results (engine.py)

When `evaluate_rules()` finds a match, it additionally scans the content line by line to record which lines matched:

- New field in result dict: `matched_lines: list[int]` (1-indexed line numbers)
- For regex matches: iterate content lines, test each against the matched pattern, collect line numbers
- For YARA matches: use `instance.offset` from the YARA match data, convert byte offsets to line numbers by counting newlines in the content up to each offset
- The existing `matched` field (first 100 chars of match text) remains unchanged

### 3. Enhanced deny/audit message (cli.py)

When `run_hook()` builds a response for a matched rule, if `matched_lines` is present and non-empty:

- **Strict mode (deny):** Build a dynamic message by appending to the rule's static message: `" Detected at lines {lines}. Ask the developer to provide a redacted version."`
- **Audit mode (allow with context):** Same line-number suffix appended to the `[AUDIT]` message, so teams in audit mode also see where sensitive content was found
- Example: *"Brazilian CPF number detected in content. Writing PII such as CPF numbers to source files may violate LGPD. Use anonymized or tokenized identifiers instead. Detected at lines 3, 7. Ask the developer to provide a redacted version."*
- Include `matched_lines` in event metadata sent to the dashboard

### 4. Typo fix (brazilian-cpf.yaml)

The rule's matcher is `Writxe|Edit|Read` — fix to `Write|Edit|Read`.

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| File doesn't exist | Skip pre-scan, allow (Claude Code shows its own error) |
| Binary file | Skip pre-scan, allow |
| File > 1MB | Skip pre-scan, allow (known gap — see Section 1) |
| Permission denied | Skip pre-scan, allow |
| Relative file path | Resolve against `hook_input["cwd"]` before opening |
| Symlinks | Follow normally — note: this means symlinks to files outside the project are followed; acceptable because path-based rules (e.g., `protected-paths`) can block specific targets |
| TOCTOU (file changes between scan and read) | Acknowledged limitation — file could be modified between hook scan and Claude's read; acceptable for a CLI tool where this window is milliseconds |
| Rule only on PostToolUse | No pre-scan (by design — rule author's choice) |
| PreToolUse blocks | PostToolUse never fires for that tool call |
| Non-Read tools at PreToolUse | No pre-scan — file reading only happens for `Read` tool |

### Files Changed

| File | Change |
|------|--------|
| `tatu-hook/src/tatu_hook/protocol.py` | `extract_content()` — add file pre-scan for Read at PreToolUse |
| `tatu-hook/src/tatu_hook/engine.py` | `evaluate_rules()` — add `matched_lines` to result dict |
| `tatu-hook/src/tatu_hook/cli.py` | `run_hook()` — append line numbers to deny and audit messages |
| `rules/pii/brazilian-cpf.yaml` | Fix typo: `Writxe` → `Write` |
| `tatu-hook/tests/` | New tests for pre-scan, line numbers, edge cases |

### Test Plan

1. **Unit: pre-scan reads file** — `extract_content()` returns file content when tool is Read + PreToolUse
2. **Unit: skip pre-scan** — missing, binary, large, and permission-denied files return only file path
3. **Unit: pre-scan resolves relative paths** — relative `file_path` resolved against `cwd`
4. **Unit: no pre-scan for non-Read tools** — Write at PreToolUse does not read any file from disk
5. **Unit: matched_lines (regex)** — `evaluate_rules()` returns correct line numbers for regex matches
6. **Unit: matched_lines (YARA)** — correct line numbers derived from YARA byte offsets
7. **Unit: deny message format** — line numbers appended correctly to deny reason
8. **Unit: audit message format** — line numbers appended correctly to audit context
9. **Integration: end-to-end** — Read of file with CPF is blocked at PreToolUse with line numbers in deny reason

## What This Does NOT Solve

This feature blocks Claude from reading files with sensitive content. It does not:

- Redact content (Claude gets nothing, not a sanitized version)
- Prevent data transmission for Write/Edit (Claude generated that content — it's already in context)
- Act as network-level DLP
- Protect files larger than 1MB (pre-scan is skipped for performance)
- Guard against TOCTOU race conditions (millisecond window, acceptable risk)

It is a **code-level guardrail** that prevents sensitive file content from entering Claude's conversation context in the first place.
