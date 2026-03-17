# tatu-hook

A security hook that evaluates security rules locally and reports events to the [Tatu DevSecOps dashboard](https://github.com/laboratorio-hacker/tatu).

## What it does

`tatu-hook` runs as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) on developer machines. It intercepts tool calls (file writes, shell commands, etc.) and evaluates them against security rules — blocking secrets, destructive commands, PII exposure, and code vulnerabilities in real time.

- **Secrets detection** — AWS keys, GitHub tokens, Stripe keys, private keys, passwords
- **PII/LGPD compliance** — Brazilian CPF/CNPJ, email addresses, credit cards
- **Destructive command blocking** — `rm -rf`, `DROP TABLE`, `git push --force`
- **SAST scanning** — SQL injection, XSS, command injection patterns
- **YARA rules** — Advanced multi-condition pattern matching

## Install

```bash
pip install tatu-hook

# With YARA rule support:
pip install "tatu-hook[yara]"
```

## Quick start

Create an API key in the Tatu dashboard (Settings > API Keys), then:

```bash
tatu-hook init --api-url https://tatu.your-domain.com --api-key tatu_xxxxx
```

This creates `~/.tatu/manifest.json`, syncs the latest rules, and registers hooks in `~/.claude/settings.json` automatically.

**Options:**
- `--scope project` — register hooks in `.claude/settings.json` (current directory) instead of globally
- `--no-register` — skip hook registration (for users who manage settings externally)

## How it works

1. **SessionStart** — Syncs rules from the Tatu API (version check, downloads only if outdated)
2. **PreToolUse / PostToolUse** — Evaluates content against cached rules (regex + optional YARA)
3. **Policy modes:**
   - `audit` (default) — Logs what would be blocked, never denies. Safe for onboarding.
   - `strict` — Actively blocks Claude Code operations that match rules.
4. Events are reported asynchronously to the dashboard (fire-and-forget, non-blocking)

## Local cache

Rules are cached at `~/.tatu/` for offline resilience:

```
~/.tatu/
├── manifest.json    # Version, API URL, API key
├── rules/           # Synced YAML rule templates
└── yara/            # Synced YARA rules
```

If the API is unreachable, `tatu-hook` falls back to cached rules silently.

## CLI reference

```bash
tatu-hook --version                          # Show version
tatu-hook init --api-url URL --api-key KEY   # Initialize configuration
tatu-hook run --event session-start          # Sync rules on session start
tatu-hook run --event pre                    # Evaluate PreToolUse hook
tatu-hook run --event post                   # Evaluate PostToolUse hook
```

## Requirements

- Python 3.10+
- PyYAML 6.0+
- (Optional) yara-python 4.5+ for YARA rule evaluation

## License

MIT
