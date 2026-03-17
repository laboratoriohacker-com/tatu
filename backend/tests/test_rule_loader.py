"""Tests for the YAML/YARA rule loader service."""

import tempfile
from pathlib import Path

import pytest

from app.services.rule_loader import (
    load_rules_from_directory,
    parse_yaml_rule,
    parse_yara_rule,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

YAML_TEMPLATE = """\
id: secrets-detector-v1
info:
  name: Secrets Detector
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
    - "(?i)(password|secret|api[_-]?key)\\\\s*[:=]\\\\s*\\\\S+"
message: "Potential secret detected in file content."
"""

YAML_TEMPLATE_NO_MODE = """\
id: no-mode-rule
info:
  name: No Mode Rule
  severity: warning
  category: compliance
hook:
  event: PostToolUse
  matcher: Bash
  action: warn
detect:
  type: regex
  patterns:
    - "TODO"
message: "Found TODO comment."
"""

YARA_TEMPLATE = """\
rule SecretsDetector
{
    meta:
        id = "yara-secrets-v1"
        name = "YARA Secrets Detector"
        severity = "critical"
        category = "secrets"
        action = "block"
        hook_event = "PreToolUse"
        matcher = "Write|Edit"
        mode = "strict"
    strings:
        $api_key = /(?i)api[_-]?key\\s*[:=]\\s*\\S+/
    condition:
        any of them
}
"""


# ---------------------------------------------------------------------------
# parse_yaml_rule
# ---------------------------------------------------------------------------

def test_parse_yaml_rule_returns_correct_fields():
    rule = parse_yaml_rule(YAML_TEMPLATE, "secrets-detector-v1.yaml")

    assert rule["id"] == "secrets-detector-v1"
    assert rule["name"] == "Secrets Detector"
    assert rule["format"] == "yaml"
    assert rule["content"] == YAML_TEMPLATE
    assert rule["enabled"] is True
    assert rule["category"] == "secrets"
    assert rule["severity"] == "critical"
    assert rule["mode"] == "strict"
    assert rule["action"] == "block"
    assert rule["hook_event"] == "PreToolUse"
    assert rule["matcher"] == "Write|Edit"
    assert rule["version_added"] == 1
    assert rule["compliance_mappings"] == []


def test_parse_yaml_rule_default_mode_is_audit_when_omitted():
    rule = parse_yaml_rule(YAML_TEMPLATE_NO_MODE, "no-mode-rule.yaml")

    assert rule["id"] == "no-mode-rule"
    assert rule["mode"] == "audit"


def test_parse_yaml_rule_preserves_original_content():
    rule = parse_yaml_rule(YAML_TEMPLATE, "secrets-detector-v1.yaml")
    assert rule["content"] == YAML_TEMPLATE


def test_parse_yaml_rule_minimal_required_fields():
    minimal = """\
id: minimal-rule
info:
  name: Minimal Rule
  severity: info
  category: misc
hook:
  event: PreToolUse
  matcher: "*"
  action: log
"""
    rule = parse_yaml_rule(minimal, "minimal.yaml")
    assert rule["id"] == "minimal-rule"
    assert rule["format"] == "yaml"


# ---------------------------------------------------------------------------
# parse_yara_rule
# ---------------------------------------------------------------------------

def test_parse_yara_rule_extracts_metadata():
    rule = parse_yara_rule(YARA_TEMPLATE, "secrets.yar")

    assert rule["id"] == "yara-secrets-v1"
    assert rule["name"] == "YARA Secrets Detector"
    assert rule["format"] == "yara"
    assert rule["content"] == YARA_TEMPLATE
    assert rule["enabled"] is True
    assert rule["category"] == "secrets"
    assert rule["severity"] == "critical"
    assert rule["action"] == "block"
    assert rule["hook_event"] == "PreToolUse"
    assert rule["matcher"] == "Write|Edit"
    assert rule["mode"] == "strict"
    assert rule["version_added"] == 1
    assert rule["compliance_mappings"] == []


def test_parse_yara_rule_uses_filename_stem_as_fallback_id():
    yara_no_id = """\
rule NoIdRule
{
    meta:
        name = "No ID Rule"
        severity = "info"
    strings:
        $dummy = "dummy"
    condition:
        $dummy
}
"""
    rule = parse_yara_rule(yara_no_id, "fallback-name.yar")
    assert rule["id"] == "fallback-name"


def test_parse_yara_rule_default_mode_is_audit_when_omitted():
    yara_no_mode = """\
rule NoModeRule
{
    meta:
        id = "no-mode-yara"
        name = "No Mode YARA"
        severity = "warning"
    strings:
        $dummy = "x"
    condition:
        $dummy
}
"""
    rule = parse_yara_rule(yara_no_mode, "no_mode.yar")
    assert rule["mode"] == "audit"


def test_parse_yara_rule_preserves_original_content():
    rule = parse_yara_rule(YARA_TEMPLATE, "secrets.yar")
    assert rule["content"] == YARA_TEMPLATE


# ---------------------------------------------------------------------------
# load_rules_from_directory
# ---------------------------------------------------------------------------

def test_load_rules_from_directory_returns_yaml_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        rule_path = Path(tmpdir) / "secrets.yaml"
        rule_path.write_text(YAML_TEMPLATE, encoding="utf-8")

        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 1
    assert rules[0]["id"] == "secrets-detector-v1"
    assert rules[0]["format"] == "yaml"


def test_load_rules_from_directory_handles_mixed_yaml_and_yara():
    with tempfile.TemporaryDirectory() as tmpdir:
        yaml_path = Path(tmpdir) / "secrets.yaml"
        yaml_path.write_text(YAML_TEMPLATE, encoding="utf-8")

        yara_path = Path(tmpdir) / "secrets.yar"
        yara_path.write_text(YARA_TEMPLATE, encoding="utf-8")

        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 2
    formats = {r["format"] for r in rules}
    assert formats == {"yaml", "yara"}


def test_load_rules_from_directory_sorts_files_deterministically():
    with tempfile.TemporaryDirectory() as tmpdir:
        for letter in ["c", "a", "b"]:
            rule_content = YAML_TEMPLATE_NO_MODE.replace("no-mode-rule", f"rule-{letter}")
            (Path(tmpdir) / f"rule_{letter}.yaml").write_text(rule_content, encoding="utf-8")

        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 3
    ids = [r["id"] for r in rules]
    assert ids == sorted(ids)


def test_load_rules_from_directory_walks_subdirectories():
    with tempfile.TemporaryDirectory() as tmpdir:
        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()
        (subdir / "deep.yaml").write_text(YAML_TEMPLATE, encoding="utf-8")

        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 1
    assert rules[0]["id"] == "secrets-detector-v1"


def test_load_rules_from_directory_ignores_non_rule_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "readme.txt").write_text("ignore me", encoding="utf-8")
        (Path(tmpdir) / "config.json").write_text("{}", encoding="utf-8")
        (Path(tmpdir) / "rule.yaml").write_text(YAML_TEMPLATE, encoding="utf-8")

        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 1


def test_load_rules_from_directory_empty_dir_returns_empty_list():
    with tempfile.TemporaryDirectory() as tmpdir:
        rules = load_rules_from_directory(tmpdir)
    assert rules == []


def test_load_rules_from_directory_accepts_yml_extension():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "rule.yml").write_text(YAML_TEMPLATE, encoding="utf-8")
        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 1
    assert rules[0]["format"] == "yaml"


def test_load_rules_from_directory_accepts_yara_extension():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "rule.yara").write_text(YARA_TEMPLATE, encoding="utf-8")
        rules = load_rules_from_directory(tmpdir)

    assert len(rules) == 1
    assert rules[0]["format"] == "yara"
