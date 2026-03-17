# Read Pre-Scan Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block sensitive content from reaching Claude's context by pre-scanning files at PreToolUse for Read operations.

**Architecture:** Add file-reading logic to `extract_content()` so that when a Read PreToolUse event arrives, the hook opens and scans the file before Claude does. Add `matched_lines` to engine results for precise reporting. Enhance deny/audit messages with line numbers.

**Tech Stack:** Python 3.11+, pytest, tatu-hook CLI

---

## Chunk 1: Pre-scan in protocol.py + tests

### Task 1: Fix typo in brazilian-cpf.yaml

**Files:**
- Modify: `rules/pii/brazilian-cpf.yaml:23`

- [ ] **Step 1: Fix the typo**

In `rules/pii/brazilian-cpf.yaml` line 23, change `Writxe|Edit|Read` to `Write|Edit|Read`.

- [ ] **Step 2: Commit**

```bash
git add rules/pii/brazilian-cpf.yaml
git commit -m "fix: correct typo in brazilian-cpf rule matcher (Writxe → Write)"
```

### Task 2: Write failing tests for extract_content pre-scan

**Files:**
- Modify: `tatu-hook/tests/test_protocol.py`

- [ ] **Step 1: Write test — pre-scan reads file at PreToolUse for Read**

Add to `test_protocol.py`:

```python
def test_extract_content_prescan_read_pretooluse(tmp_path):
    """PreToolUse + Read should open and scan the actual file."""
    target = tmp_path / "data.txt"
    target.write_text("line1\nCPF: 928.385.640-64\nline3\n")
    hook_input = {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_response": {},
        "cwd": str(tmp_path),
    }
    content = extract_content(hook_input)
    assert "928.385.640-64" in content
    assert str(target) in content  # file_path still included
```

- [ ] **Step 2: Write test — pre-scan resolves relative path against cwd**

```python
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
```

- [ ] **Step 3: Write test — skip pre-scan for missing file**

```python
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
```

- [ ] **Step 4: Write test — skip pre-scan for binary file**

```python
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
```

- [ ] **Step 5: Write test — skip pre-scan for large file (>1MB)**

```python
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
```

- [ ] **Step 6: Write test — no pre-scan for Write at PreToolUse**

```python
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
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_protocol.py -v -k prescan"`

Expected: All 6 new tests FAIL (pre-scan not implemented yet).

- [ ] **Step 8: Commit failing tests**

```bash
git add tatu-hook/tests/test_protocol.py
git commit -m "test(protocol): add failing tests for Read pre-scan at PreToolUse"
```

### Task 3: Implement pre-scan in extract_content

**Files:**
- Modify: `tatu-hook/src/tatu_hook/protocol.py:32-79`

- [ ] **Step 1: Add pre-scan logic to extract_content**

In `protocol.py`, modify `extract_content()`. After the existing `if tool_name in ("Write", "Read"):` block (lines 42-48), add pre-scan logic. Replace the block with:

```python
        if tool_name in ("Write", "Read"):
            content = tool_input.get("content", "")
            if content:
                parts.append(content)
            file_path = tool_input.get("file_path", "")
            if file_path:
                parts.append(file_path)
            # Pre-scan: read file from disk for Read at PreToolUse
            if tool_name == "Read" and hook_event == "PreToolUse" and file_path:
                resolved = file_path
                if not os.path.isabs(resolved):
                    cwd = hook_input.get("cwd", "")
                    if cwd:
                        resolved = os.path.join(cwd, resolved)
                try:
                    size = os.path.getsize(resolved)
                    if size <= 1_048_576:  # 1MB limit
                        with open(resolved, encoding="utf-8") as f:
                            file_content = f.read()
                        parts.append(file_content)
                except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError):
                    pass  # skip pre-scan, allow Claude Code to handle
```

- [ ] **Step 2: Run pre-scan tests to verify they pass**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_protocol.py -v -k prescan"`

Expected: All 6 pre-scan tests PASS.

- [ ] **Step 3: Run full protocol test suite**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_protocol.py -v"`

Expected: All tests PASS (no regressions).

- [ ] **Step 4: Commit**

```bash
git add tatu-hook/src/tatu_hook/protocol.py
git commit -m "feat(protocol): pre-scan files at PreToolUse for Read operations

Opens and scans the actual file content before Claude reads it.
Skips pre-scan for missing, binary, >1MB, or unreadable files."
```

## Chunk 2: matched_lines in engine.py + tests

### Task 4: Write failing tests for matched_lines

**Files:**
- Modify: `tatu-hook/tests/test_engine.py`

- [ ] **Step 1: Write test — matched_lines for regex**

Add to `test_engine.py` inside `TestEvaluateRules`:

```python
    def test_matched_lines_for_regex(self):
        rules = self._load_block_rule()
        content = "line1 safe\nline2 AKIAIOSFODNN7EXAMPLE\nline3 safe\nline4 AKIAI12345678ABCDE"
        results = evaluate_rules(rules, "Write", content)
        assert len(results) == 1
        assert results[0]["matched_lines"] == [2, 4]
```

- [ ] **Step 2: Write test — matched_lines empty when match is in single-line content**

```python
    def test_matched_lines_single_line(self):
        rules = self._load_block_rule()
        content = "AKIAIOSFODNN7EXAMPLE"
        results = evaluate_rules(rules, "Write", content)
        assert len(results) == 1
        assert results[0]["matched_lines"] == [1]
```

- [ ] **Step 3: Write test — matched_lines absent when no match**

```python
    def test_no_matched_lines_when_no_match(self):
        rules = self._load_block_rule()
        content = "safe content"
        results = evaluate_rules(rules, "Write", content)
        assert results == []
```

- [ ] **Step 4: Write test — matched_lines for YARA**

Add to `TestEvaluateYaraRules`:

```python
    def test_yara_matched_lines(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "line1 safe\nline2 SUPERSECRET here\nline3 safe"
            results = evaluate_rules(rules, "Write", content)
            assert len(results) == 1
            assert results[0]["matched_lines"] == [2]
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_engine.py -v -k matched_lines"`

Expected: All new tests FAIL (matched_lines not implemented).

- [ ] **Step 6: Commit failing tests**

```bash
git add tatu-hook/tests/test_engine.py
git commit -m "test(engine): add failing tests for matched_lines in evaluate_rules"
```

### Task 5: Implement matched_lines in evaluate_rules

**Files:**
- Modify: `tatu-hook/src/tatu_hook/engine.py:87-137`

- [ ] **Step 1: Add helper function for line number extraction**

Add before `evaluate_rules()`:

```python
def _find_matched_lines(content: str, pattern: re.Pattern) -> list[int]:
    """Return 1-indexed line numbers where pattern matches."""
    lines = []
    for i, line in enumerate(content.split("\n"), start=1):
        if pattern.search(line):
            lines.append(i)
    return lines


def _offsets_to_lines(content: str, offsets: list[int]) -> list[int]:
    """Convert byte offsets to 1-indexed line numbers."""
    content_bytes = content.encode()
    lines = set()
    for offset in offsets:
        line_num = content_bytes[:offset].count(b"\n") + 1
        lines.add(line_num)
    return sorted(lines)
```

- [ ] **Step 2: Add matched_lines to regex match results**

In `evaluate_rules()`, in the regex match branch (after `break` on line 136), add `matched_lines` to the result dict. Replace the regex results.append block:

```python
                if match:
                    matched_lines = _find_matched_lines(content, pattern)
                    results.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "action": rule["action"],
                        "mode": rule["mode"],
                        "message": rule["message"],
                        "matched": match.group(0)[:100],
                        "matched_lines": matched_lines,
                    })
                    break  # one match per rule
```

- [ ] **Step 3: Add matched_lines to YARA match results**

In the YARA branch, collect offsets from all string instances and convert to line numbers. Replace the YARA results.append block:

```python
            if matches:
                matched_text = ""
                offsets = []
                for string_match in matches[0].strings:
                    for instance in string_match.instances:
                        if not matched_text:
                            matched_text = instance.matched_data.decode(errors="replace")[:100]
                        offsets.append(instance.offset)
                if not matched_text:
                    matched_text = matches[0].rule
                matched_lines = _offsets_to_lines(content, offsets) if offsets else []
                results.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "action": rule["action"],
                    "mode": rule["mode"],
                    "message": rule["message"],
                    "matched": matched_text,
                    "matched_lines": matched_lines,
                })
```

- [ ] **Step 4: Run matched_lines tests**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_engine.py -v -k matched_lines"`

Expected: All matched_lines tests PASS.

- [ ] **Step 5: Run full engine test suite**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_engine.py -v"`

Expected: All tests PASS (no regressions).

- [ ] **Step 6: Commit**

```bash
git add tatu-hook/src/tatu_hook/engine.py
git commit -m "feat(engine): add matched_lines to evaluate_rules results

For regex rules, iterates content line by line to find matching lines.
For YARA rules, converts byte offsets to line numbers."
```

## Chunk 3: Enhanced deny/audit messages in cli.py + tests

### Task 6: Write failing tests for line numbers in messages

**Files:**
- Modify: `tatu-hook/tests/test_cli.py`

- [ ] **Step 1: Add CPF rule constant and Read pre-scan test fixtures**

Add to `test_cli.py` after the existing rule constants:

```python
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
```

- [ ] **Step 2: Write test — deny message includes line numbers**

```python
class TestRunHookLineNumbers:
    def test_deny_message_includes_line_numbers(self, tmp_path):
        """Strict block should append line numbers to deny message."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        target = tmp_path / "data.txt"
        target.write_text("safe\n928.385.640-64\nsafe\n111.222.333-44\n")

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
```

- [ ] **Step 3: Write test — audit message includes line numbers**

```python
    def test_audit_message_includes_line_numbers(self, tmp_path):
        """Audit block should append line numbers to audit context."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_AUDIT_RULE)

        target = tmp_path / "data.txt"
        target.write_text("safe\n928.385.640-64\nsafe\n")

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
```

- [ ] **Step 4: Add `import os` to test_cli.py**

Add `import os` to the imports at the top of `tatu-hook/tests/test_cli.py` (it is not currently imported).

- [ ] **Step 5: Update existing tests that use exact equality on context**

After Tasks 5+7, the engine always returns `matched_lines` and `run_hook` enhances the message. Existing tests that assert exact equality on `result["context"]` will break. Update them to use substring checks.

In `TestRunHookStrictBlock`, change:

```python
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
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_cli.py -v -k 'LineNumbers'"`

Expected: Both tests FAIL (line numbers not appended yet).

- [ ] **Step 7: Commit failing tests**

```bash
git add tatu-hook/tests/test_cli.py
git commit -m "test(cli): add failing tests for line numbers in deny/audit messages"
```

### Task 7: Implement line numbers in deny/audit messages

**Files:**
- Modify: `tatu-hook/src/tatu_hook/cli.py:69-125`

- [ ] **Step 1: Add helper to build message with line numbers**

Add before `run_hook()` in `cli.py`:

```python
def _enhance_message(message: str, matched_lines: list[int]) -> str:
    """Append line numbers to a rule message if available."""
    if not matched_lines:
        return message
    if len(matched_lines) == 1:
        lines_str = f"line {matched_lines[0]}"
    else:
        lines_str = f"lines {', '.join(str(n) for n in matched_lines)}"
    return f"{message} Detected at {lines_str}. Ask the developer to provide a redacted version."
```

- [ ] **Step 2: Use enhanced message in run_hook**

In `run_hook()`, modify the block that builds responses (lines 116-123). Replace:

```python
        if match["action"] == "block":
            if match["mode"] == "strict":
                return {"decision": "deny", "context": match["message"]}
            elif match["mode"] == "audit":
                return {"decision": "allow", "context": f"[AUDIT] {match['message']}"}

        if match["action"] == "warn":
            return {"decision": "allow", "context": match["message"]}
```

With:

```python
        matched_lines = match.get("matched_lines", [])

        if match["action"] == "block":
            enhanced = _enhance_message(match["message"], matched_lines)
            if match["mode"] == "strict":
                return {"decision": "deny", "context": enhanced}
            elif match["mode"] == "audit":
                return {"decision": "allow", "context": f"[AUDIT] {enhanced}"}

        if match["action"] == "warn":
            return {"decision": "allow", "context": match["message"]}
```

- [ ] **Step 3: Include matched_lines in event metadata**

In the `report_event` call (line 108-113), add `matched_lines` to metadata. Replace:

```python
            "metadata": {
                "rule_id": match["rule_id"],
                "category": match["category"],
                "matched_text": match.get("matched", ""),
                "file_path": file_path,
            },
```

With:

```python
            "metadata": {
                "rule_id": match["rule_id"],
                "category": match["category"],
                "matched_text": match.get("matched", ""),
                "matched_lines": match.get("matched_lines", []),
                "file_path": file_path,
            },
```

- [ ] **Step 4: Run line number tests**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_cli.py -v -k 'LineNumbers'"`

Expected: Both tests PASS.

- [ ] **Step 5: Run full CLI test suite**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_cli.py -v"`

Expected: All tests PASS (no regressions).

- [ ] **Step 6: Commit**

```bash
git add tatu-hook/src/tatu_hook/cli.py
git commit -m "feat(cli): append line numbers to deny and audit messages

Enhanced messages tell Claude which lines contain sensitive content
and instruct it to ask the developer for a redacted version."
```

## Chunk 4: Full integration test + final verification

### Task 8: Integration test — end-to-end Read pre-scan block

**Files:**
- Modify: `tatu-hook/tests/test_cli.py`

- [ ] **Step 1: Write end-to-end integration test**

Add to `test_cli.py`:

```python
class TestRunHookReadPreScan:
    def test_read_prescan_blocks_cpf_at_pretooluse(self, tmp_path):
        """End-to-end: Read of file with CPF is blocked at PreToolUse."""
        tatu_dir = str(tmp_path / "tatu")
        os.makedirs(tatu_dir)
        _setup_dir(tatu_dir, CPF_BLOCK_RULE)

        target = tmp_path / "client_data.txt"
        target.write_text(
            "Client: João Silva\n"
            "CPF: 928.385.640-64\n"
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
```

- [ ] **Step 2: Run integration tests**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/test_cli.py::TestRunHookReadPreScan -v"`

Expected: Both tests PASS.

- [ ] **Step 3: Run full test suite**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m pytest tests/ -v"`

Expected: ALL tests PASS across all test files.

- [ ] **Step 4: Lint**

Run: `docker compose run --rm backend bash -c "cd /app/tatu-hook && python -m flake8 src/ tests/ --max-line-length=120"` (or the project's configured linter)

Expected: No lint errors.

- [ ] **Step 5: Commit integration tests**

```bash
git add tatu-hook/tests/test_cli.py
git commit -m "test(cli): add end-to-end integration tests for Read pre-scan"
```
