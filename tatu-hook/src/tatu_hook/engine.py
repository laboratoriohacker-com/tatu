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
        else:
            for pattern in rule["patterns"]:
                match = pattern.search(content)
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
    return results
