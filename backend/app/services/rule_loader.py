"""
YAML and YARA rule loader service.

Provides parsers for individual rule files and a directory walker that
discovers and parses all rules under a given path.
"""

import os
import re
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------

def parse_yaml_rule(content: str, filename: str) -> dict:
    """Parse a YAML rule file and return a dict compatible with the Rule model.

    Expected structure::

        id: rule-id
        info:
          name: Rule Name
          severity: critical
          category: secrets
        hook:
          event: PreToolUse
          matcher: Write|Edit
          action: block
          mode: audit        # optional – defaults to "audit"
        detect:
          type: regex
          patterns: [...]
        message: "..."

    Returns a dict with keys: id, name, format, content, enabled, category,
    severity, mode, action, hook_event, matcher, version_added.
    """
    data = yaml.safe_load(content)

    info = data.get("info", {})
    hook = data.get("hook", {})

    return {
        "id": data["id"],
        "name": info.get("name", data["id"]),
        "format": "yaml",
        "content": content,
        "enabled": True,
        "category": info.get("category", ""),
        "severity": info.get("severity", "info"),
        "mode": hook.get("mode", "audit"),
        "action": hook.get("action", "log"),
        "hook_event": ",".join(hook["events"]) if "events" in hook else hook.get("event", "PreToolUse"),
        "matcher": hook.get("matcher", "*"),
        "version_added": 1,
        "compliance_mappings": info.get("compliance", []),
    }


# ---------------------------------------------------------------------------
# YARA parser
# ---------------------------------------------------------------------------

_META_LINE_RE = re.compile(
    r"""^\s*(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))\s*$"""
)


def _parse_meta_block(content: str) -> dict:
    """Extract key/value pairs from the first ``meta:`` block in a YARA rule."""
    in_meta = False
    meta: dict = {}
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "meta:":
            in_meta = True
            continue
        if in_meta:
            # Any new section keyword ends the meta block
            if stripped and not stripped.startswith("//") and ":" in stripped and not stripped.startswith('"'):
                # Check if this looks like a section header (no leading spaces
                # relative to "meta:" or a known YARA section name)
                section_match = re.match(r"^\s*(strings|condition|meta)\s*:", line)
                if section_match:
                    break
            m = _META_LINE_RE.match(line)
            if m:
                key = m.group(1)
                # First non-None capture group among groups 2-4
                value = m.group(2) if m.group(2) is not None else (
                    m.group(3) if m.group(3) is not None else m.group(4)
                )
                meta[key] = value
    return meta


def parse_yara_rule(content: str, filename: str) -> dict:
    """Parse a YARA rule file and return a dict compatible with the Rule model.

    Metadata extracted from the ``meta:`` block. Falls back to the filename
    stem when no ``id`` field is present in meta.

    Returns a dict with the same keys as ``parse_yaml_rule``.
    """
    meta = _parse_meta_block(content)

    stem = Path(filename).stem
    rule_id = meta.get("id", stem)

    return {
        "id": rule_id,
        "name": meta.get("name", rule_id),
        "format": "yara",
        "content": content,
        "enabled": True,
        "category": meta.get("category", ""),
        "severity": meta.get("severity", "info"),
        "mode": meta.get("mode", "audit"),
        "action": meta.get("action", "log"),
        "hook_event": meta.get("hook_event", "PreToolUse"),
        "matcher": meta.get("matcher", "*"),
        "version_added": 1,
        "compliance_mappings": [],
    }


# ---------------------------------------------------------------------------
# Directory loader
# ---------------------------------------------------------------------------

def load_rules_from_directory(rules_dir: str) -> list[dict]:
    """Walk *rules_dir* recursively and parse every YAML/YARA rule file found.

    Files are processed in sorted order for deterministic results.  Parsing
    errors are silently skipped so that a single malformed file does not abort
    the entire load.

    Returns a list of rule dicts.
    """
    rules: list[dict] = []
    all_paths: list[Path] = []

    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            all_paths.append(Path(root) / fname)

    all_paths.sort()

    for path in all_paths:
        suffix = path.suffix.lower()
        if suffix not in {".yaml", ".yml", ".yar", ".yara"}:
            continue

        content = path.read_text(encoding="utf-8")
        try:
            if suffix in {".yaml", ".yml"}:
                rule = parse_yaml_rule(content, path.name)
            else:
                rule = parse_yara_rule(content, path.name)
        except Exception:
            continue

        rules.append(rule)

    return rules
