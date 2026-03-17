"""Rule sync client — downloads rules from Tatu API on SessionStart."""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error


TATU_DIR = os.path.expanduser("~/.tatu")


def ensure_tatu_dir(base: str | None = None) -> str:
    d = base or TATU_DIR
    os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(d, "rules"), exist_ok=True)
    os.makedirs(os.path.join(d, "yara"), exist_ok=True)
    return d


def load_manifest(base: str | None = None) -> dict:
    d = base or TATU_DIR
    path = os.path.join(d, "manifest.json")
    if not os.path.exists(path):
        return {"version": 0, "api_url": "", "api_key": "", "updated_at": "", "rule_count": 0}
    with open(path) as f:
        return json.load(f)


def save_manifest(base: str, manifest: dict) -> None:
    ensure_tatu_dir(base)
    path = os.path.join(base, "manifest.json")
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)


def save_rules_to_cache(base: str, rules: list[dict]) -> None:
    ensure_tatu_dir(base)
    rules_dir = os.path.join(base, "rules")
    yara_dir = os.path.join(base, "yara")
    # Clear existing cached rules
    for d in (rules_dir, yara_dir):
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
    for rule in rules:
        if rule["format"] == "yara":
            path = os.path.join(yara_dir, f"{rule['id']}.yar")
        else:
            path = os.path.join(rules_dir, f"{rule['id']}.yaml")
        with open(path, "w") as f:
            f.write(rule["content"])


def load_rules_from_cache(base: str | None = None) -> list[dict]:
    d = base or TATU_DIR
    rules = []
    rules_dir = os.path.join(d, "rules")
    yara_dir = os.path.join(d, "yara")
    if os.path.isdir(rules_dir):
        for filename in sorted(os.listdir(rules_dir)):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath) as f:
                content = f.read()
            rule_id = os.path.splitext(filename)[0]
            rules.append({"id": rule_id, "format": "yaml", "content": content, "source_dir": rules_dir})
    if os.path.isdir(yara_dir):
        for filename in sorted(os.listdir(yara_dir)):
            filepath = os.path.join(yara_dir, filename)
            with open(filepath) as f:
                content = f.read()
            rule_id = os.path.splitext(filename)[0]
            rules.append({"id": rule_id, "format": "yara", "content": content, "source_dir": yara_dir})
    return rules


def sync_rules(base: str | None = None) -> list[dict]:
    """Check version and download rules if outdated. Returns loaded rules."""
    d = base or TATU_DIR
    manifest = load_manifest(d)
    api_url = manifest.get("api_url", "")
    api_key = manifest.get("api_key", "")
    local_version = manifest.get("version", 0)
    if not api_url or not api_key:
        return load_rules_from_cache(d)
    try:
        url = f"{api_url}/api/v1/rules/sync?version={local_version}"
        req = urllib.request.Request(url, headers={"X-API-Key": api_key})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return load_rules_from_cache(d)
    if data.get("status") == "up_to_date":
        return load_rules_from_cache(d)
    rules = data.get("rules", [])
    save_rules_to_cache(d, rules)
    save_manifest(d, {
        **manifest,
        "version": data["version"],
        "updated_at": data.get("updated_at", ""),
        "rule_count": len(rules),
    })
    return rules
