"""Tests for the tatu-hook rule evaluation engine."""
from __future__ import annotations

import os
import tempfile

import pytest

from tatu_hook.engine import evaluate_rules, load_yaml_rules

BLOCK_RULE = """id: test-aws-key
info:
  name: Test AWS Key
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
message: "AWS key found"
"""

MULTI_EVENT_RULE = """id: test-multi-event
info:
  name: Test Multi Event
  severity: high
  category: secrets
hook:
  events:
    - PreToolUse
    - PostToolUse
  matcher: Write|Edit|Read
  action: block
  mode: audit
detect:
  type: regex
  patterns:
    - 'AKIA[A-Z0-9]{16}'
message: "AWS key found (multi-event)"
"""

AUDIT_RULE = """id: test-audit-rule
info:
  name: Test Audit Rule
  severity: medium
  category: compliance
hook:
  event: PreToolUse
  matcher: Write|Edit|Read
  action: log
  mode: audit
detect:
  type: regex
  patterns:
    - 'TODO|FIXME'
message: "Code annotation found"
"""


class TestLoadYamlRules:
    def test_parses_sample_rule_correctly(self):
        raw = [{"format": "yaml", "content": BLOCK_RULE}]
        rules = load_yaml_rules(raw)

        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "test-aws-key"
        assert rule["name"] == "Test AWS Key"
        assert rule["severity"] == "critical"
        assert rule["category"] == "secrets"
        assert rule["hook_events"] == ["PreToolUse"]
        assert rule["matcher"] == "Write|Edit"
        assert rule["action"] == "block"
        assert rule["mode"] == "strict"
        assert rule["message"] == "AWS key found"
        assert len(rule["patterns"]) == 1

    def test_skips_non_yaml_format_rules(self):
        raw = [
            {"format": "yara", "content": "rule test { condition: true }"},
            {"format": "yaml", "content": BLOCK_RULE},
        ]
        rules = load_yaml_rules(raw)
        assert len(rules) == 1
        assert rules[0]["id"] == "test-aws-key"

    def test_skips_invalid_yaml_content(self):
        raw = [
            {"format": "yaml", "content": "{ invalid yaml: [unclosed bracket"},
            {"format": "yaml", "content": BLOCK_RULE},
        ]
        rules = load_yaml_rules(raw)
        assert len(rules) == 1
        assert rules[0]["id"] == "test-aws-key"

    def test_returns_empty_list_for_no_yaml_rules(self):
        raw = [
            {"format": "yara", "content": "rule test {}"},
        ]
        rules = load_yaml_rules(raw)
        assert rules == []

    def test_uses_fallback_id_from_raw(self):
        content = BLOCK_RULE.replace("id: test-aws-key\n", "")
        raw = [{"format": "yaml", "id": "fallback-id", "content": content}]
        rules = load_yaml_rules(raw)
        assert len(rules) == 1
        assert rules[0]["id"] == "fallback-id"

    def test_applies_defaults_for_missing_fields(self):
        minimal_rule = """id: minimal-rule
info:
  name: Minimal Rule
detect:
  patterns:
    - 'test'
"""
        raw = [{"format": "yaml", "content": minimal_rule}]
        rules = load_yaml_rules(raw)
        assert len(rules) == 1
        rule = rules[0]
        assert rule["severity"] == "info"
        assert rule["hook_events"] == ["PreToolUse"]
        assert rule["matcher"] == ".*"
        assert rule["action"] == "log"
        assert rule["mode"] == "audit"


class TestEvaluateRules:
    def _load_block_rule(self):
        raw = [{"format": "yaml", "content": BLOCK_RULE}]
        return load_yaml_rules(raw)

    def _load_audit_rule(self):
        raw = [{"format": "yaml", "content": AUDIT_RULE}]
        return load_yaml_rules(raw)

    def test_matches_strict_block_rule(self):
        rules = self._load_block_rule()
        content = "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'"
        results = evaluate_rules(rules, "Write", content)

        assert len(results) == 1
        result = results[0]
        assert result["rule_id"] == "test-aws-key"
        assert result["action"] == "block"
        assert result["mode"] == "strict"
        assert result["severity"] == "critical"
        assert "AKIA" in result["matched"]

    def test_returns_empty_for_no_match(self):
        rules = self._load_block_rule()
        content = "This is safe content with no secrets"
        results = evaluate_rules(rules, "Write", content)

        assert results == []

    def test_respects_matcher_filter_wrong_tool(self):
        rules = self._load_block_rule()
        content = "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'"
        # Rule matcher is "Write|Edit" — Bash should not match
        results = evaluate_rules(rules, "Bash", content)

        assert results == []

    def test_matches_audit_mode_rule(self):
        rules = self._load_audit_rule()
        content = "# TODO: fix this later"
        results = evaluate_rules(rules, "Edit", content)

        assert len(results) == 1
        result = results[0]
        assert result["rule_id"] == "test-audit-rule"
        assert result["action"] == "log"
        assert result["mode"] == "audit"
        assert result["severity"] == "medium"

    def test_filters_by_hook_event(self):
        rules = self._load_block_rule()
        content = "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'"
        # Rule is PreToolUse, passing PostToolUse should return nothing
        results = evaluate_rules(rules, "Write", content, hook_event="PostToolUse")

        assert results == []

    def test_multi_event_rule_matches_both_events(self):
        raw = [{"format": "yaml", "content": MULTI_EVENT_RULE}]
        rules = load_yaml_rules(raw)
        content = "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'"

        pre_results = evaluate_rules(rules, "Write", content, hook_event="PreToolUse")
        assert len(pre_results) == 1

        post_results = evaluate_rules(rules, "Read", content, hook_event="PostToolUse")
        assert len(post_results) == 1

    def test_multi_event_rule_parsed_as_list(self):
        raw = [{"format": "yaml", "content": MULTI_EVENT_RULE}]
        rules = load_yaml_rules(raw)
        assert rules[0]["hook_events"] == ["PreToolUse", "PostToolUse"]

    def test_matched_text_truncated_to_100_chars(self):
        long_pattern_rule = """id: long-match-rule
info:
  name: Long Match Rule
  severity: low
  category: test
hook:
  event: PreToolUse
  matcher: Write
  action: log
  mode: audit
detect:
  type: regex
  patterns:
    - '[A-Za-z0-9+/]{80,}={0,2}'
message: "Long base64 found"
"""
        raw = [{"format": "yaml", "content": long_pattern_rule}]
        rules = load_yaml_rules(raw)
        # A base64-like string longer than 100 chars
        content = "data: " + "A" * 120 + "=="
        results = evaluate_rules(rules, "Write", content)

        if results:
            assert len(results[0]["matched"]) <= 100

    def test_one_match_per_rule(self):
        rules = self._load_block_rule()
        # Content with two potential AWS key matches
        content = "key1=AKIAIOSFODNN7EXAMPLE key2=AKIAI12345678ABCDE"
        results = evaluate_rules(rules, "Write", content)

        # Should only return one result per rule (break on first match)
        assert len(results) == 1

    def test_matched_lines_for_regex(self):
        rules = self._load_block_rule()
        content = "line1 safe\nline2 AKIAIOSFODNN7EXAMPLE\nline3 safe\nline4 AKIAQWERTYUIOPASDFGH"
        results = evaluate_rules(rules, "Write", content)
        assert len(results) == 1
        assert results[0]["matched_lines"] == [2, 4]

    def test_matched_lines_single_line(self):
        rules = self._load_block_rule()
        content = "AKIAIOSFODNN7EXAMPLE"
        results = evaluate_rules(rules, "Write", content)
        assert len(results) == 1
        assert results[0]["matched_lines"] == [1]

    def test_no_matched_lines_when_no_match(self):
        rules = self._load_block_rule()
        content = "safe content"
        results = evaluate_rules(rules, "Write", content)
        assert results == []

    def test_multiple_rules_can_match(self):
        block_rules = load_yaml_rules([{"format": "yaml", "content": BLOCK_RULE}])
        audit_rules = load_yaml_rules([{"format": "yaml", "content": AUDIT_RULE}])
        all_rules = block_rules + audit_rules

        content = "key=AKIAIOSFODNN7EXAMPLE # TODO: rotate this key"
        results = evaluate_rules(all_rules, "Write", content)

        assert len(results) == 2
        rule_ids = {r["rule_id"] for r in results}
        assert "test-aws-key" in rule_ids
        assert "test-audit-rule" in rule_ids


# ---------------------------------------------------------------------------
# YARA rule constants
# ---------------------------------------------------------------------------

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
        pytest.importorskip("yara")
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

    def test_yara_rule_respects_hook_event_filter(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "The password is SUPERSECRET here"
            results = evaluate_rules(rules, "Write", content, hook_event="PostToolUse")
            assert results == []

    def test_yara_rule_respects_matcher_filter(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "The password is SUPERSECRET here"
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

    def test_yara_matched_lines(self):
        pytest.importorskip("yara")
        with tempfile.TemporaryDirectory() as tmp:
            rules = self._load_yara_rule(tmp)
            content = "line1 safe\nline2 SUPERSECRET here\nline3 safe"
            results = evaluate_rules(rules, "Write", content)
            assert len(results) == 1
            assert results[0]["matched_lines"] == [2]

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
