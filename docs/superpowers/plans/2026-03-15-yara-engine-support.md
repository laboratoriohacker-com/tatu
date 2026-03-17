# YARA Engine Support Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add YARA rule evaluation to tatu-hook so `.yar` files referenced from YAML rules actually fire.

**Architecture:** Extend `load_yaml_rules()` to handle `detect.type: "yara"` by compiling the referenced `.yar` file with `yara-python`. Extend `evaluate_rules()` to match content against compiled YARA rules. `yara-python` remains optional — YARA rules are silently skipped if not installed.

**Tech Stack:** Python 3.10+, yara-python>=4.5 (optional), pytest, pyyaml

**Spec:** `docs/superpowers/specs/2026-03-15-yara-engine-support-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `tatu-hook/src/tatu_hook/engine.py` | Add YARA compilation + evaluation paths |
| Modify | `tatu-hook/src/tatu_hook/sync.py:54-73` | Add `source_dir` to rule dicts |
| Create | `rules/yara/private-key-multi.yaml` | YAML wrapper referencing the `.yar` |
| Modify | `tatu-hook/tests/test_engine.py` | YARA test cases |
| Modify | `docker-compose.yml:94` | Install `.[dev,yara]` for tests |

---

## Chunk 1: Docker Setup & Sync Layer

### Task 0: Update docker compose to install yara-python for tests

**Files:**
- Modify: `docker-compose.yml:94`

> **Why first:** All YARA tests use `pytest.importorskip("yara")` and will be silently skipped if `yara-python` is not installed. Installing it first ensures tests actually run during development.

- [ ] **Step 1: Update the tatu-hook-test entrypoint**

In `docker-compose.yml`, change line 94 from:
```yaml
    entrypoint: ["sh", "-c", "pip install -e '.[dev]' -q && python -m pytest tests/ -v"]
```
to:
```yaml
    entrypoint: ["sh", "-c", "pip install -e '.[dev,yara]' -q && python -m pytest tests/ -v"]
```

- [ ] **Step 2: Run test suite to verify nothing breaks**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: ALL existing tests PASS

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "ci: install yara-python in tatu-hook test container"
```

### Task 1: Add `source_dir` to `load_rules_from_cache`

### Task 1: Add `source_dir` to `load_rules_from_cache`

**Files:**
- Modify: `tatu-hook/src/tatu_hook/sync.py:54-73`
- Test: `tatu-hook/tests/test_sync.py`

- [ ] **Step 1: Write failing test**

Add to `tatu-hook/tests/test_sync.py`:

```python
def test_load_rules_from_cache_includes_source_dir():
    with tempfile.TemporaryDirectory() as tmp:
        rules = [
            {"id": "rule-001", "format": "yaml", "content": "id: rule-001\n"},
        ]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        assert len(loaded) == 1
        assert "source_dir" in loaded[0]
        assert loaded[0]["source_dir"] == os.path.join(tmp, "rules")


def test_load_yara_rules_from_cache_includes_source_dir():
    with tempfile.TemporaryDirectory() as tmp:
        rules = [
            {"id": "yara-001", "format": "yara", "content": "rule test { condition: true }"},
        ]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        yara_rules = [r for r in loaded if r["format"] == "yara"]
        assert len(yara_rules) == 1
        assert yara_rules[0]["source_dir"] == os.path.join(tmp, "yara")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: FAIL — `source_dir` key not present in returned dicts.

- [ ] **Step 3: Implement `source_dir` in `load_rules_from_cache`**

In `tatu-hook/src/tatu_hook/sync.py`, modify `load_rules_from_cache()`. Change line 65:
```python
            rules.append({"id": rule_id, "format": "yaml", "content": content, "source_dir": rules_dir})
```

Change line 72:
```python
            rules.append({"id": rule_id, "format": "yara", "content": content, "source_dir": yara_dir})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/sync.py tatu-hook/tests/test_sync.py
git commit -m "feat(sync): add source_dir to cached rule dicts"
```

---

## Chunk 2: Engine — YARA Loading in `load_yaml_rules`

### Task 2: Create the YAML wrapper rule file

**Files:**
- Create: `rules/yara/private-key-multi.yaml`

- [ ] **Step 1: Create the YAML wrapper**

Create `rules/yara/private-key-multi.yaml`:

```yaml
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
  yara_file: private-key-multi.yar
message: "PEM private key detected in content. Remove private keys from source files."
```

- [ ] **Step 2: Commit**

```bash
git add rules/yara/private-key-multi.yaml
git commit -m "feat(rules): add YAML wrapper for YARA private-key rule"
```

### Task 3: Add YARA loading to engine

**Files:**
- Modify: `tatu-hook/src/tatu_hook/engine.py`
- Test: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write failing test — YARA rule loads and compiles**

Add a test `.yar` file as a constant and test class to `tatu-hook/tests/test_engine.py`:

```python
import os
import tempfile

TEST_YARA_CONTENT = """rule test_secret {
  strings:
    $s = "SUPERSECRET" ascii
  condition:
    $s
}
"""

YARA_YAML_RULE = """id: test-yara-rule
info:
  name: Test YARA Rule
  severity: critical
  category: secrets
hook:
  events:
    - PreToolUse
  matcher: Write|Edit
  action: block
  mode: strict
detect:
  type: yara
  yara_file: test-secret.yar
message: "Secret found via YARA"
"""


class TestLoadYaraRules:
    def _create_yara_rule(self, tmp_dir):
        """Write a .yar file to tmp_dir and return a raw rule dict."""
        yar_path = os.path.join(tmp_dir, "test-secret.yar")
        with open(yar_path, "w") as f:
            f.write(TEST_YARA_CONTENT)
        return {
            "format": "yaml",
            "content": YARA_YAML_RULE,
            "source_dir": tmp_dir,
        }

    def test_yara_rule_loads_and_compiles(self):
        yara = pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            raw = [self._create_yara_rule(tmp)]
            rules = load_yaml_rules(raw)
            assert len(rules) == 1
            rule = rules[0]
            assert rule["id"] == "test-yara-rule"
            assert rule["name"] == "Test YARA Rule"
            assert rule["severity"] == "critical"
            assert rule["yara_rules"] is not None
            assert rule["patterns"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: FAIL — `yara_rules` key not in rule dict.

- [ ] **Step 3: Implement YARA loading in `load_yaml_rules`**

Replace everything from the top of `tatu-hook/src/tatu_hook/engine.py` through the end of `load_yaml_rules` (lines 1-42). Keep `evaluate_rules` unchanged:

```python
"""Rule evaluation engine for tatu-hook."""
from __future__ import annotations

import os
import re
from typing import Any

import yaml

try:
    import yara
except ImportError:
    yara = None


def _compile_yara(yar_path: str):
    """Compile a .yar file. Returns compiled rules or None on error."""
    if yara is None:
        return None
    try:
        return yara.compile(filepath=yar_path)
    except (yara.SyntaxError, yara.Error):
        return None


def _resolve_yara_path(yara_file: str, source_dir: str) -> str | None:
    """Resolve yara_file relative to source_dir. Returns None if unsafe or missing."""
    if not yara_file or os.path.isabs(yara_file) or ".." in yara_file:
        return None
    resolved = os.path.join(source_dir, yara_file)
    if not os.path.isfile(resolved):
        return None
    return resolved


def load_yaml_rules(raw_rules: list[dict]) -> list[dict]:
    """Parse raw rule dicts (with 'content' field) into evaluable rules."""
    parsed = []
    for raw in raw_rules:
        if raw.get("format") != "yaml":
            continue
        try:
            data = yaml.safe_load(raw["content"])
        except yaml.YAMLError:
            continue
        info = data.get("info", {})
        hook = data.get("hook", {})
        detect = data.get("detect", {})
        detect_type = detect.get("type", "regex")

        compiled_patterns = []
        compiled_yara = None

        if detect_type == "yara":
            source_dir = raw.get("source_dir", "")
            yara_file = detect.get("yara_file", "")
            yar_path = _resolve_yara_path(yara_file, source_dir)
            if yar_path is None:
                continue
            compiled_yara = _compile_yara(yar_path)
            if compiled_yara is None:
                continue
        else:
            patterns = detect.get("patterns", [])
            for p in patterns:
                try:
                    compiled_patterns.append(re.compile(p))
                except re.error:
                    continue

        parsed.append({
            "id": data.get("id", raw.get("id", "unknown")),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "category": info.get("category", ""),
            "hook_events": hook.get("events") or [hook.get("event", "PreToolUse")],
            "matcher": hook.get("matcher", ".*"),
            "action": hook.get("action", "log"),
            "mode": hook.get("mode", "audit"),
            "patterns": compiled_patterns,
            "yara_rules": compiled_yara,
            "message": data.get("message", ""),
        })
    return parsed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: PASS for `test_yara_rule_loads_and_compiles`, all existing tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/engine.py tatu-hook/tests/test_engine.py
git commit -m "feat(engine): add YARA rule loading to load_yaml_rules"
```

### Task 4: Test YARA loading edge cases

**Files:**
- Test: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write edge case tests**

Add to `TestLoadYaraRules` class in `tatu-hook/tests/test_engine.py`:

```python
    def test_skips_yara_rule_when_yara_not_installed(self, monkeypatch):
        import tatu_hook.engine as engine_mod
        monkeypatch.setattr(engine_mod, "yara", None)
        with tempfile.TemporaryDirectory() as tmp:
            raw = [self._create_yara_rule(tmp)]
            rules = load_yaml_rules(raw)
            assert rules == []

    def test_skips_yara_rule_when_yar_file_missing(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            # Don't create the .yar file — only the YAML wrapper
            raw = [{
                "format": "yaml",
                "content": YARA_YAML_RULE,
                "source_dir": tmp,
            }]
            rules = load_yaml_rules(raw)
            assert rules == []

    def test_skips_yara_rule_with_absolute_path(self):
        pytest.importorskip("yara")
        bad_rule = YARA_YAML_RULE.replace(
            "yara_file: test-secret.yar",
            "yara_file: /etc/passwd",
        )
        with tempfile.TemporaryDirectory() as tmp:
            raw = [{"format": "yaml", "content": bad_rule, "source_dir": tmp}]
            rules = load_yaml_rules(raw)
            assert rules == []

    def test_skips_yara_rule_with_path_traversal(self):
        pytest.importorskip("yara")
        bad_rule = YARA_YAML_RULE.replace(
            "yara_file: test-secret.yar",
            "yara_file: ../../../etc/passwd",
        )
        with tempfile.TemporaryDirectory() as tmp:
            raw = [{"format": "yaml", "content": bad_rule, "source_dir": tmp}]
            rules = load_yaml_rules(raw)
            assert rules == []

    def test_skips_yara_rule_with_syntax_error(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            yar_path = os.path.join(tmp, "test-secret.yar")
            with open(yar_path, "w") as f:
                f.write("rule broken { strings: $s = condition: }")
            raw = [{"format": "yaml", "content": YARA_YAML_RULE, "source_dir": tmp}]
            rules = load_yaml_rules(raw)
            assert rules == []

    def test_skips_yara_rule_without_yara_file_field(self):
        pytest.importorskip("yara")
        no_file_rule = YARA_YAML_RULE.replace("  yara_file: test-secret.yar\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            raw = [{"format": "yaml", "content": no_file_rule, "source_dir": tmp}]
            rules = load_yaml_rules(raw)
            assert rules == []
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add tatu-hook/tests/test_engine.py
git commit -m "test(engine): add YARA loading edge case tests"
```

---

## Chunk 3: Engine — YARA Evaluation in `evaluate_rules`

### Task 5: Add YARA matching to `evaluate_rules`

**Files:**
- Modify: `tatu-hook/src/tatu_hook/engine.py:45-73`
- Test: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write failing test — YARA rule matches content**

Add to `tatu-hook/tests/test_engine.py`:

```python
class TestEvaluateYaraRules:
    def _load_yara_rule(self, tmp_dir):
        yar_path = os.path.join(tmp_dir, "test-secret.yar")
        with open(yar_path, "w") as f:
            f.write(TEST_YARA_CONTENT)
        raw = [{"format": "yaml", "content": YARA_YAML_RULE, "source_dir": tmp_dir}]
        return load_yaml_rules(raw)

    def test_yara_rule_matches_content(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "The password is SUPERSECRET here"
            results = evaluate_rules(rules, "Write", content)
            assert len(results) == 1
            result = results[0]
            assert result["rule_id"] == "test-yara-rule"
            assert result["action"] == "block"
            assert result["mode"] == "strict"
            assert result["severity"] == "critical"
            assert "SUPERSECRET" in result["matched"]

    def test_yara_rule_no_match_on_clean_content(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "This is safe content with no secrets"
            results = evaluate_rules(rules, "Write", content)
            assert results == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: FAIL — `evaluate_rules` does not check `yara_rules`.

- [ ] **Step 3: Implement YARA matching in `evaluate_rules`**

Replace the `evaluate_rules` function in `tatu-hook/src/tatu_hook/engine.py`:

```python
def evaluate_rules(
    rules: list[dict],
    tool_name: str,
    content: str,
    hook_event: str = "PreToolUse",
) -> list[dict]:
    """Evaluate content against rules. Returns list of matched rule results."""
    results = []
    for rule in rules:
        if hook_event not in rule["hook_events"]:
            continue
        matcher_re = re.compile(rule["matcher"])
        if not matcher_re.search(tool_name):
            continue

        yara_compiled = rule.get("yara_rules")
        if yara_compiled is not None:
            matches = yara_compiled.match(data=content.encode())
            if matches:
                matched_text = ""
                if matches[0].strings:
                    instances = matches[0].strings[0].instances
                    if instances:
                        matched_text = instances[0].matched_data.decode(errors="replace")[:100]
                if not matched_text:
                    matched_text = matches[0].rule
                results.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "action": rule["action"],
                    "mode": rule["mode"],
                    "message": rule["message"],
                    "matched": matched_text,
                })
        else:
            for pattern in rule["patterns"]:
                match = pattern.search(content)
                if match:
                    results.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "action": rule["action"],
                        "mode": rule["mode"],
                        "message": rule["message"],
                        "matched": match.group(0)[:100],
                    })
                    break  # one match per rule
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add tatu-hook/src/tatu_hook/engine.py tatu-hook/tests/test_engine.py
git commit -m "feat(engine): add YARA matching to evaluate_rules"
```

### Task 6: Test YARA evaluation edge cases

**Files:**
- Test: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write remaining evaluation tests**

Add to `TestEvaluateYaraRules` class:

```python
    def test_yara_rule_respects_hook_event_filter(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "The password is SUPERSECRET here"
            # Rule has events: [PreToolUse], passing PostToolUse should return nothing
            results = evaluate_rules(rules, "Write", content, hook_event="PostToolUse")
            assert results == []

    def test_yara_rule_respects_matcher_filter(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "The password is SUPERSECRET here"
            # Rule matcher is Write|Edit — Bash should not match
            results = evaluate_rules(rules, "Bash", content)
            assert results == []

    def test_mixed_regex_and_yara_rules(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            yara_rules = self._load_yara_rule(tmp)
            regex_rules = load_yaml_rules([{"format": "yaml", "content": AUDIT_RULE}])
            all_rules = yara_rules + regex_rules
            content = "SUPERSECRET # TODO: rotate this"
            results = evaluate_rules(all_rules, "Write", content)
            assert len(results) == 2
            rule_ids = {r["rule_id"] for r in results}
            assert "test-yara-rule" in rule_ids
            assert "test-audit-rule" in rule_ids

    def test_yara_matched_text_truncated_to_100_chars(self):
        pytest.importorskip("yara")
        long_yar = """rule long_match {
  strings:
    $s = /[A-Z]{80,}/
  condition:
    $s
}
"""
        long_yaml = """id: test-long-yara
info:
  name: Long YARA Match
  severity: low
  category: test
hook:
  events:
    - PreToolUse
  matcher: Write
  action: log
  mode: audit
detect:
  type: yara
  yara_file: long.yar
message: "Long match"
"""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "long.yar"), "w") as f:
                f.write(long_yar)
            raw = [{"format": "yaml", "content": long_yaml, "source_dir": tmp}]
            rules = load_yaml_rules(raw)
            content = "A" * 150
            results = evaluate_rules(rules, "Write", content)
            assert len(results) == 1
            assert len(results[0]["matched"]) <= 100
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `docker compose --profile tatu-hook-test run --rm tatu-hook-test`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add tatu-hook/tests/test_engine.py
git commit -m "test(engine): add YARA evaluation edge case tests"
```

---

## Chunk 4: Integration

### Task 7: End-to-end smoke test with private key rule

- [ ] **Step 1: Run the hook manually against a PEM key**

Create a temp file with PEM content and pipe it through the hook to verify the real `private-key-multi.yar` rule fires:

```bash
# From inside the tatu-hook-test container or local env with yara installed:
echo '{"tool_name": "Write", "tool_input": {"content": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----"}}' | \
  python -c "
import json, sys, tempfile, os
sys.path.insert(0, 'src')
from tatu_hook.engine import load_yaml_rules, evaluate_rules
# Load the real YAML wrapper + .yar
rules_dir = '../rules/yara'
with open(os.path.join(rules_dir, 'private-key-multi.yaml')) as f:
    content = f.read()
raw = [{'format': 'yaml', 'content': content, 'source_dir': rules_dir}]
rules = load_yaml_rules(raw)
inp = json.load(sys.stdin)
results = evaluate_rules(rules, inp['tool_name'], inp['tool_input']['content'])
print(json.dumps(results, indent=2))
"
```

Expected: One result with `rule_id: yara-private-key`, `action: block`.

- [ ] **Step 2: Final commit — all done**

```bash
git add -A
git commit -m "feat: add YARA rule evaluation support to tatu-hook engine"
```
