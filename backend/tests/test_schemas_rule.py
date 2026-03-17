import pytest
from pydantic import ValidationError
from app.schemas.rule import (
    RuleCreate,
    RuleSyncItem,
    RuleSyncResponse,
    RuleSyncUpToDate,
)


VALID_RULE_DATA = dict(
    id="secrets-detector-001",
    name="Secrets Leak Prevention",
    format="yaml",
    content="patterns:\n  - AWS_KEY",
    category="secrets",
    severity="critical",
    action="block",
    hook_event="PreToolUse",
    matcher="Write|Edit",
)


def test_rule_create_valid():
    rule = RuleCreate(**VALID_RULE_DATA)
    assert rule.id == "secrets-detector-001"
    assert rule.name == "Secrets Leak Prevention"
    assert rule.format == "yaml"
    assert rule.severity == "critical"
    assert rule.action == "block"
    assert rule.hook_event == "PreToolUse"


def test_rule_create_default_mode_is_audit():
    rule = RuleCreate(**VALID_RULE_DATA)
    assert rule.mode == "audit"


def test_rule_create_explicit_strict_mode():
    rule = RuleCreate(**{**VALID_RULE_DATA, "mode": "strict"})
    assert rule.mode == "strict"


def test_rule_create_rejects_invalid_format():
    with pytest.raises(ValidationError):
        RuleCreate(**{**VALID_RULE_DATA, "format": "json"})


def test_rule_create_rejects_invalid_mode():
    with pytest.raises(ValidationError):
        RuleCreate(**{**VALID_RULE_DATA, "mode": "passive"})


def test_rule_create_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        RuleCreate(**{**VALID_RULE_DATA, "severity": "high"})


def test_rule_create_rejects_invalid_action():
    with pytest.raises(ValidationError):
        RuleCreate(**{**VALID_RULE_DATA, "action": "deny"})


def test_rule_create_rejects_invalid_hook_event():
    with pytest.raises(ValidationError):
        RuleCreate(**{**VALID_RULE_DATA, "hook_event": "OnSave"})


def test_rule_create_yara_format():
    rule = RuleCreate(**{**VALID_RULE_DATA, "format": "yara"})
    assert rule.format == "yara"


def test_rule_sync_response_construction():
    items = [
        RuleSyncItem(id="rule-001", format="yaml", content="patterns: []"),
        RuleSyncItem(id="rule-002", format="yara", content="rule test {}"),
    ]
    resp = RuleSyncResponse(
        version=42,
        updated_at="2026-03-14T00:00:00Z",
        rules=items,
    )
    assert resp.version == 42
    assert resp.updated_at == "2026-03-14T00:00:00Z"
    assert len(resp.rules) == 2
    assert resp.rules[0].id == "rule-001"
    assert resp.rules[1].format == "yara"


def test_rule_sync_up_to_date_construction():
    result = RuleSyncUpToDate(version=42)
    assert result.version == 42
    assert result.status == "up_to_date"


def test_rule_sync_up_to_date_custom_status():
    result = RuleSyncUpToDate(version=10, status="custom")
    assert result.status == "custom"
