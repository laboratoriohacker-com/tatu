"""Tests for the rule sync client module."""
from __future__ import annotations

import os
import tempfile

import pytest

from tatu_hook.sync import (
    ensure_tatu_dir,
    load_manifest,
    load_rules_from_cache,
    save_manifest,
    save_rules_to_cache,
)


# ---------------------------------------------------------------------------
# ensure_tatu_dir
# ---------------------------------------------------------------------------

def test_ensure_tatu_dir_creates_subdirectories():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "tatu")
        result = ensure_tatu_dir(base)
        assert result == base
        assert os.path.isdir(os.path.join(base, "rules"))
        assert os.path.isdir(os.path.join(base, "yara"))


def test_ensure_tatu_dir_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "tatu")
        ensure_tatu_dir(base)
        # Should not raise
        ensure_tatu_dir(base)
        assert os.path.isdir(os.path.join(base, "rules"))


# ---------------------------------------------------------------------------
# manifest roundtrip
# ---------------------------------------------------------------------------

def test_manifest_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = {
            "version": 42,
            "api_url": "https://tatu.example.com",
            "api_key": "secret-key",
            "updated_at": "2026-03-14T00:00:00Z",
            "rule_count": 7,
        }
        save_manifest(tmp, manifest)
        loaded = load_manifest(tmp)
        assert loaded["version"] == 42
        assert loaded["api_url"] == "https://tatu.example.com"
        assert loaded["api_key"] == "secret-key"
        assert loaded["rule_count"] == 7


def test_manifest_missing_returns_defaults():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "fresh")
        os.makedirs(base)
        result = load_manifest(base)
        assert result["version"] == 0
        assert result["api_url"] == ""
        assert result["api_key"] == ""
        assert result["rule_count"] == 0


# ---------------------------------------------------------------------------
# rules cache roundtrip
# ---------------------------------------------------------------------------

def test_save_and_load_rules_yaml():
    with tempfile.TemporaryDirectory() as tmp:
        rules = [
            {"id": "rule-001", "format": "yaml", "content": "id: rule-001\nname: test\n"},
            {"id": "rule-002", "format": "yaml", "content": "id: rule-002\nname: other\n"},
        ]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        ids = {r["id"] for r in loaded}
        assert "rule-001" in ids
        assert "rule-002" in ids
        for r in loaded:
            assert r["format"] == "yaml"


def test_save_and_load_rules_yara():
    with tempfile.TemporaryDirectory() as tmp:
        rules = [
            {"id": "yara-001", "format": "yara", "content": "rule yara_001 { condition: true }"},
        ]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        yara_rules = [r for r in loaded if r["format"] == "yara"]
        assert len(yara_rules) == 1
        assert yara_rules[0]["id"] == "yara-001"
        assert "condition: true" in yara_rules[0]["content"]


def test_save_and_load_rules_mixed_formats():
    with tempfile.TemporaryDirectory() as tmp:
        rules = [
            {"id": "yaml-rule", "format": "yaml", "content": "id: yaml-rule\n"},
            {"id": "yara-rule", "format": "yara", "content": "rule yara_rule { condition: false }"},
        ]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        formats = {r["format"] for r in loaded}
        assert "yaml" in formats
        assert "yara" in formats
        assert len(loaded) == 2


def test_save_rules_clears_previous_cache():
    with tempfile.TemporaryDirectory() as tmp:
        old_rules = [
            {"id": "old-rule", "format": "yaml", "content": "id: old-rule\n"},
        ]
        save_rules_to_cache(tmp, old_rules)

        new_rules = [
            {"id": "new-rule", "format": "yaml", "content": "id: new-rule\n"},
        ]
        save_rules_to_cache(tmp, new_rules)

        loaded = load_rules_from_cache(tmp)
        ids = {r["id"] for r in loaded}
        assert "old-rule" not in ids
        assert "new-rule" in ids


def test_load_rules_from_cache_empty_directory():
    with tempfile.TemporaryDirectory() as tmp:
        ensure_tatu_dir(tmp)
        loaded = load_rules_from_cache(tmp)
        assert loaded == []


def test_load_rules_content_matches():
    with tempfile.TemporaryDirectory() as tmp:
        content = "id: check-secrets\npattern: SECRET_KEY\n"
        rules = [{"id": "check-secrets", "format": "yaml", "content": content}]
        save_rules_to_cache(tmp, rules)
        loaded = load_rules_from_cache(tmp)
        assert len(loaded) == 1
        assert loaded[0]["content"] == content


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
