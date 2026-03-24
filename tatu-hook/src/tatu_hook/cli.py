"""Tatu Hook — Claude Code security hook CLI."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from tatu_hook import __version__
from tatu_hook.engine import load_yaml_rules, evaluate_rules
from tatu_hook.protocol import (
    parse_hook_input,
    extract_content,
    format_allow_response,
    format_deny_response,
)
from tatu_hook.sync import load_manifest, save_manifest, load_rules_from_cache, sync_rules, ensure_tatu_dir
from tatu_hook.reporter import report_event, flush as flush_reports
from tatu_hook.platform import (
    resolve_config_path,
    get_hook_entries,
    has_tatu_hook as platform_has_tatu_hook,
)

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "critical",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


def _derive_status(action: str, mode: str) -> str:
    if action == "block" and mode == "strict":
        return "blocked"
    if action == "block" and mode == "audit":
        return "audit_block"
    if action == "warn":
        return "warning"
    return "allowed"


def _git_config(key: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "config", "--get", key],
            stderr=subprocess.DEVNULL, timeout=2,
        ).decode().strip()
    except Exception:
        return ""


def _get_developer() -> str:
    return os.environ.get("USER") or _git_config("user.name") or "unknown"


def _get_repository() -> str:
    try:
        toplevel = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL, timeout=2,
        ).decode().strip()
        return os.path.basename(toplevel)
    except Exception:
        return os.path.basename(os.getcwd())


def _get_session_id() -> str:
    return os.environ.get("CLAUDE_SESSION_ID", "cli")


def _enhance_message(message: str, matched_lines: list[int]) -> str:
    """Append line numbers to a rule message if available."""
    if not matched_lines:
        return message
    if len(matched_lines) == 1:
        lines_str = f"line {matched_lines[0]}"
    else:
        lines_str = f"lines {', '.join(str(n) for n in matched_lines)}"
    return f"{message} Detected at {lines_str}. Ask the developer to provide a redacted version."


_HOOK_ENTRIES = {
    "SessionStart": {
        "hooks": [{"type": "command", "command": "tatu-hook run --event session-start"}],
    },
    "PreToolUse": {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": "tatu-hook run --event pre"}],
    },
    "PostToolUse": {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": "tatu-hook run --event post"}],
    },
}


def _has_tatu_hook(entries: list) -> bool:
    """Check if tatu-hook is already registered in a hook event array."""
    for entry in entries:
        for hook_obj in entry.get("hooks", []):
            if "tatu-hook run" in hook_obj.get("command", ""):
                return True
    return False


def _resolve_settings_path(scope: str) -> str:
    """Resolve the Claude Code settings.json path."""
    if scope == "project":
        return os.path.join(os.getcwd(), ".claude", "settings.json")
    return os.path.expanduser(os.path.join("~", ".claude", "settings.json"))


def register_hooks(scope: str = "global") -> tuple[str, bool]:
    """Register tatu-hook in Claude Code settings.json.

    Returns (settings_path, was_modified).
    """
    settings_path = _resolve_settings_path(scope)

    # Create parent directory if needed
    parent = os.path.dirname(settings_path)
    os.makedirs(parent, exist_ok=True)

    # Read existing settings
    settings = {}
    if os.path.exists(settings_path):
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)

    # Ensure hooks dict exists
    if "hooks" not in settings:
        settings["hooks"] = {}

    modified = False
    for event_name, entry in _HOOK_ENTRIES.items():
        if event_name not in settings["hooks"]:
            settings["hooks"][event_name] = []
        if not _has_tatu_hook(settings["hooks"][event_name]):
            settings["hooks"][event_name].append(entry)
            modified = True

    if modified:
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")

    return settings_path, modified


def register_hooks_cursor(scope: str = "global") -> tuple[str, bool]:
    """Register tatu-hook in Cursor hooks.json.

    Returns (config_path, was_modified).
    """
    config_path = resolve_config_path("cursor", scope)
    parent = os.path.dirname(config_path)
    os.makedirs(parent, exist_ok=True)

    config = {"version": 1, "hooks": {}}
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        if "hooks" not in config:
            config["hooks"] = {}

    entries = get_hook_entries("cursor")
    modified = False
    for event_name, event_entries in entries.items():
        if event_name not in config["hooks"]:
            config["hooks"][event_name] = []
        if not platform_has_tatu_hook("cursor", config["hooks"][event_name]):
            config["hooks"][event_name].extend(event_entries)
            modified = True

    if modified:
        config["version"] = 1
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")

    return config_path, modified


def run_hook(event: str, raw_input: str, tatu_dir: str | None = None) -> dict:
    """Core hook execution pipeline.

    Returns a dict with keys:
      - decision: "allow" or "deny"
      - context: optional string message (None if no match)
    """
    manifest = load_manifest(tatu_dir)
    raw_rules = load_rules_from_cache(tatu_dir)
    rules = load_yaml_rules(raw_rules)

    hook_input = parse_hook_input(raw_input)
    content = extract_content(hook_input)

    tool_name = hook_input.get("tool_name", "")
    hook_event_name = "PreToolUse" if event == "pre" else "PostToolUse"

    results = evaluate_rules(rules, tool_name, content, hook_event_name)

    api_url = manifest.get("api_url", "")
    api_key = manifest.get("api_key", "")

    developer = _get_developer()
    repository = _get_repository()
    session_id = hook_input.get("session_id") or _get_session_id()
    tool_input = hook_input.get("tool_input", {})
    file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""

    for match in results:
        report_event(api_url, api_key, {
            "hook_name": match["rule_name"],
            "hook_event": hook_event_name,
            "severity": _SEVERITY_MAP.get(match["severity"], "info"),
            "status": _derive_status(match["action"], match["mode"]),
            "message": match["message"],
            "developer": developer,
            "repository": repository,
            "session_id": session_id,
            "tool_name": tool_name,
            "metadata": {
                "rule_id": match["rule_id"],
                "category": match["category"],
                "matched_text": match.get("matched", ""),
                "matched_lines": match.get("matched_lines", []),
                "file_path": file_path,
            },
        })

        matched_lines = match.get("matched_lines", [])

        if match["action"] == "block":
            enhanced = _enhance_message(match["message"], matched_lines)
            if match["mode"] == "strict":
                return {"decision": "deny", "context": enhanced}
            elif match["mode"] == "audit":
                return {"decision": "allow", "context": f"[AUDIT] {enhanced}"}

        if match["action"] == "warn":
            return {"decision": "allow", "context": match["message"]}

    return {"decision": "allow", "context": None}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"Tatu Hook v{__version__} — Claude Code security hook"
    )
    p.add_argument("--version", action="version", version=f"tatu-hook {__version__}")
    sub = p.add_subparsers(dest="command")

    init_parser = sub.add_parser("init", help="Initialize tatu-hook configuration")
    init_parser.add_argument("--api-url", required=True, help="Tatu API base URL")
    init_parser.add_argument("--api-key", required=True, help="Tatu API key")
    init_parser.add_argument("--tatu-dir", default=None, help="Override tatu directory")
    init_parser.add_argument("--scope", choices=["global", "project"], default="global",
                             help="Where to register hooks (default: global)")
    init_parser.add_argument("--no-register", action="store_true",
                             help="Skip hook registration in Claude Code settings")
    init_parser.add_argument("--platform", choices=["claude", "cursor"], default="claude",
                             help="Target platform (default: claude)")

    run_parser = sub.add_parser("run", help="Run hook event handler")
    run_parser.add_argument(
        "--event", choices=["session-start", "pre", "post", "pre-shell", "pre-read"], required=True,
    )
    run_parser.add_argument("--tatu-dir", default=None, help="Override tatu directory")

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "init":
        tatu_dir = args.tatu_dir
        ensure_tatu_dir(tatu_dir)
        manifest = {
            "version": 0,
            "api_url": args.api_url,
            "api_key": args.api_key,
            "updated_at": "",
            "rule_count": 0,
        }
        save_manifest(tatu_dir or __import__("tatu_hook.sync", fromlist=["TATU_DIR"]).TATU_DIR, manifest)
        rules = sync_rules(tatu_dir)
        print(f"Initialized tatu-hook. Synced {len(rules)} rule(s).")

        if not args.no_register:
            try:
                if args.platform == "cursor":
                    path, modified = register_hooks_cursor(args.scope)
                else:
                    path, modified = register_hooks(args.scope)
                if modified:
                    print(f"Registered hooks in {path}")
                else:
                    print(f"Hooks already registered in {path}")
            except (json.JSONDecodeError, ValueError):
                print(f"Warning: Could not parse config — skipping hook registration.", file=sys.stderr)
            except OSError as e:
                print(f"Warning: Could not register hooks — {e}", file=sys.stderr)

        sys.exit(0)

    if args.command == "run":
        tatu_dir = args.tatu_dir
        event = args.event

        if event == "session-start":
            rules = sync_rules(tatu_dir)
            hook_event_name = "SessionStart"
            response = format_allow_response(hook_event_name, f"Synced {len(rules)} rule(s).")
            sys.stdout.write(response + "\n")
            sys.exit(0)

        raw_input = sys.stdin.read()

        if event == "pre":
            hook_event_name = "PreToolUse"
        else:
            hook_event_name = "PostToolUse"

        result = run_hook(event, raw_input, tatu_dir)

        if result["decision"] == "deny":
            response = format_deny_response(hook_event_name, result["context"] or "Blocked by policy")
            sys.stderr.write(response + "\n")
            flush_reports()
            sys.exit(2)
        else:
            response = format_allow_response(hook_event_name, result["context"])
            sys.stdout.write(response + "\n")
            flush_reports()
            sys.exit(0)


if __name__ == "__main__":
    main()
