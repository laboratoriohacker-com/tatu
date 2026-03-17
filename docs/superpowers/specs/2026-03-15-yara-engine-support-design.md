# YARA Engine Support Design

**Date:** 2026-03-15
**Status:** Approved

## Goal

Add YARA rule evaluation support to tatu-hook's engine so `.yar` rules actually fire when matching content is detected.

## Approach

YARA rules are referenced from standard YAML rule files via a new `detect.type: "yara"` + `detect.yara_file` field. This keeps a single rule definition format (YAML) with YARA as a detection backend alongside regex.

`yara-python` remains an optional dependency — rules with `detect.type: "yara"` are silently skipped if the library is not installed.

## YAML Rule Format

```yaml
# rules/yara/private-key-multi.yaml
id: yara-private-key
info:
  name: Private Key Detection (YARA)
  severity: critical
  category: secrets
  author: tatu
  tags: [secrets, pem, private-key]
  compliance: [SOC2, ISO27001]
hook:
  events:
    - PreToolUse
  matcher: Write|Edit|Read
  action: block
  mode: audit
detect:
  type: yara
  yara_file: private-key-multi.yar   # resolved relative to the YAML file's directory
message: "PEM private key detected in content. Remove private keys from source files."
```

The `.yar` file stays pure YARA — any `meta:` block in the `.yar` file is ignored by the engine (the YAML wrapper is the single source of truth for metadata).

## Engine Changes

### `engine.py`

**Import guard:**
```python
try:
    import yara
except ImportError:
    yara = None
```

**`load_yaml_rules(raw_rules)`:**
- Existing `format != "yaml"` filter continues to gate entry — YAML-wrapper rules for YARA have `format: "yaml"` so they pass through.
- When `detect.type == "yara"`:
  - If `yara` is `None` (not installed), skip the rule silently.
  - Resolve `detect.yara_file` relative to the rule's `source_dir` (see below). Only relative paths are accepted — reject absolute paths or paths containing `..` to prevent path traversal.
  - If the resolved `.yar` file does not exist, skip the rule silently.
  - Compile with `yara.compile(filepath=resolved_path)`. Catch `yara.SyntaxError` and `yara.Error` — skip the rule silently on compilation failure.
  - Store the compiled YARA rules object as `rule["yara_rules"]`. The `patterns` list remains empty.
- When `detect.type` is absent or `"regex"` (default), existing regex behavior is unchanged.

**Source directory via `source_dir` on rule dict:**
Each raw rule dict gets a `source_dir` key populated by the loader (see sync changes below). `load_yaml_rules()` signature does not change — it reads `source_dir` from each raw rule dict.

**`evaluate_rules()`:**
- For each matched rule (passes hook_event and matcher filters), check if `rule.get("yara_rules")` is set.
  - If YARA: call `yara_rules.match(data=content.encode())` and check for matches.
  - If regex: existing pattern search (unchanged).
- For YARA match results, populate the `matched` field from the first matched string's data, truncated to 100 chars: `matches[0].strings[0].instances[0].matched_data.decode(errors="replace")[:100]`. If no string data is available, use the YARA rule name.

### `sync.py` / `load_rules_from_cache()`

- Add `source_dir` key to each returned rule dict, set to the directory containing the cached rule file.
- No other sync changes in this iteration.

### `cli.py`

- No signature changes needed (source_dir travels on the rule dict).
- Minor: when loading rules from local files (non-cache path, if any), ensure `source_dir` is populated.

### Sync layer limitation

API-fetched YARA rules currently land in `~/.tatu/yara/` with `format: "yara"` and no YAML wrapper. These will **not** fire in this iteration — the API would need to serve YAML+YARA pairs. This is out of scope and documented as a known limitation.

## File Changes

1. **`rules/yara/private-key-multi.yaml`** — new YAML rule file referencing existing `.yar`
2. **`engine.py`** — extend `load_yaml_rules()` and `evaluate_rules()` for YARA support
3. **`sync.py`** — add `source_dir` to rule dicts in `load_rules_from_cache()`
4. **`tests/test_engine.py`** — comprehensive YARA tests (see below)

## Error Handling

All errors during YARA rule loading are handled by silently skipping the rule, consistent with existing error handling for bad YAML and bad regex patterns:

| Error | Behavior |
|---|---|
| `yara-python` not installed | Skip rule |
| `.yar` file not found | Skip rule |
| `.yar` path is absolute or contains `..` | Skip rule |
| YARA compilation error | Skip rule |
| `detect.yara_file` field missing | Skip rule |

## Graceful Fallback

If `yara-python` is not installed:
- `load_yaml_rules()` skips rules with `detect.type: "yara"`
- All other YAML/regex rules continue to work normally

## Test Plan

| Case | Description |
|---|---|
| YARA rule loads and compiles | Valid `.yaml` + `.yar` pair loads correctly |
| YARA rule matches content | Private key content triggers a match |
| YARA rule does not match clean content | Safe content returns no results |
| Graceful skip — no yara-python | Monkeypatch `yara` to `None`, rule is skipped |
| `.yar` file not found | Missing file path, rule skipped silently |
| `.yar` syntax error | Invalid YARA syntax, rule skipped silently |
| YARA rule respects `hook_events` filter | Wrong event returns no results |
| YARA rule respects `matcher` filter | Wrong tool name returns no results |
| `matched` field populated correctly | First matched string data, truncated to 100 chars |
| Mixed regex + YARA rules | Both types evaluate together correctly |
| `detect.type: "yara"` without `yara_file` | Rule skipped silently |

Tests use `pytest` with `monkeypatch` for mocking (consistent with project conventions).
