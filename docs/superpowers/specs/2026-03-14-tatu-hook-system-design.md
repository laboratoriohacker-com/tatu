# Tatu Hook System — Design Spec

> **Date:** 2026-03-14
> **Author:** Julio Melo + Claude
> **Status:** Approved

## Overview

A hybrid hook system for the Tatu DevSecOps platform that provides local-first security blocking for Claude Code with remote rule management and event reporting. Combines Nuclei-style YAML templates with YARA rules for comprehensive detection.

## Architecture

### Hybrid Model

- **Local-first blocking:** The `tatu-hook` CLI runs on the developer's machine as a Claude Code hook. It evaluates rules locally for instant block/allow decisions with zero network latency.
- **Remote reporting:** After each decision, `tatu-hook` fires an async (non-blocking) HTTP POST to the Tatu API to report the event. The dashboard shows real-time alerts and metrics.
- **Dynamic rule sync:** On `SessionStart`, `tatu-hook` checks its local rule version against the server. If outdated, it downloads the full updated ruleset. If the API is unreachable, it falls back to cached rules silently.

### Components

```
┌─────────────────────────────────────────────────┐
│  Tatu Dashboard (API)                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Rules DB │  │ Version  │  │ Custom rules │  │
│  │ (cached) │  │ registry │  │ editor (UI)  │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│                                                 │
│  GET /api/v1/rules/sync?version=X               │
│  POST /api/v1/events (event reporting)          │
└──────────────────┬──────────────────────────────┘
                   │
                   │ HTTP (SessionStart only for sync)
                   │
┌──────────────────▼──────────────────────────────┐
│  tatu-hook (local CLI on developer machine)     │
│  ┌──────────────────────────────────────────┐   │
│  │ Rule Engine                              │   │
│  │  ├─ YAML template loader                 │   │
│  │  ├─ YARA rule loader                     │   │
│  │  └─ Evaluator (regex + yara match)       │   │
│  └──────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────┐   │
│  │ Local cache (~/.tatu/)                   │   │
│  │  ├─ rules/          (synced templates)   │   │
│  │  ├─ yara/           (synced .yar files)  │   │
│  │  └─ manifest.json   (version + metadata) │   │
│  └──────────────────────────────────────────┘   │
└──────────────────┬──────────────────────────────┘
                   │
                   │ stdin/stdout (Claude Code hook protocol)
                   │
┌──────────────────▼──────────────────────────────┐
│  Claude Code                                    │
│  PreToolUse / PostToolUse / SessionStart / ...   │
└─────────────────────────────────────────────────┘
```

## Policy Mode

Each rule has a `mode` field that controls enforcement behavior:

- **`audit`** (default) — Rule evaluates and matches, but never blocks. Events are reported to the dashboard with `status: audit_block` so teams can see exactly what *would* be blocked. Safe for onboarding.
- **`strict`** — Rule is fully enforced. A matching `action: block` rule will deny the Claude Code operation.

| mode | action: block | action: warn |
|---|---|---|
| **audit** | Allows, reports as `audit_block` to dashboard | Allows with warning context |
| **strict** | Blocks Claude Code (deny, exit 2) | Allows with warning context |

**Default is `audit`** — secure visibility without disruption. Teams explicitly opt rules into `strict` when ready to enforce.

**Dashboard:** Audit events display with a distinct "AUDIT" badge (separate from real blocks). The Live Alerts page supports filtering by mode to answer "what would strict mode look like?"

## Rule Formats

### YAML Templates (Nuclei-style)

```yaml
id: aws-secret-access-key
info:
  name: AWS Secret Access Key
  author: tatu-core
  severity: critical
  category: secrets
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  description: Detects AWS secret access keys in code and configuration files.
  tags:
    - aws
    - cloud

hook:
  event: PreToolUse
  matcher: Write|Edit|Bash
  action: block
  mode: audit          # audit (default) = log only | strict = enforce block

detect:
  type: regex
  patterns:
    - '(?i)aws_secret_access_key\s*[:=]\s*[''"]?([A-Za-z0-9/+=]{40})'
    - '\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b'

message: "AWS secret access key detected — submission blocked"
```

### YARA Rules

```yara
rule private_key_pem {
  meta:
    id = "private-key-pem"
    severity = "critical"
    category = "secrets"
    action = "block"
    mode = "audit"
    hook_event = "PreToolUse"
    matcher = "Write|Edit|Read"
  strings:
    $begin = "-----BEGIN" ascii
    $private = "PRIVATE KEY-----" ascii
  condition:
    $begin and $private
}
```

Both formats share: `id`, `severity`, `category`, `action` (block/warn/log), `mode` (audit/strict, default audit), `hook_event`, and `matcher`. The hook engine loads both and evaluates them uniformly.

## Rule Library (Two-Layer)

### Layer 1: Built-in Rules (shipped with tatu-hook)

Organized in a `rules/` directory:

```
rules/
├── secrets/          # AWS, GitHub, GitLab, Slack, Stripe, Google, Anthropic,
│                     # OpenAI, private keys (PEM/SSH), passwords, basic auth
├── pii/              # Brazilian CPF, CNPJ, phone, email, credit cards (LGPD)
├── destructive/      # rm -rf, DROP TABLE, git push --force, chmod 777,
│                     # mkfs, dd, truncate
├── sast/             # SQL injection (string concat/f-string/format),
│                     # XSS (innerHTML, document.write),
│                     # command injection (os.system, subprocess shell=True),
│                     # path traversal (../)
├── files/            # Protected paths (.env, .github/workflows, /etc/shadow,
│                     # SSH keys), lockfile modifications
└── yara/             # Private key multi-condition, binary secrets,
                      # high-entropy blob detection
```

Approximately 40-50 templates in the initial library.

### Layer 2: Custom Rules (per org, via dashboard)

- Created and edited in the Tatu dashboard UI
- Stored in the database, served via the sync API
- If a custom rule has the same `id` as a built-in, the custom one wins (org override)

## Sync Protocol

### Version Scheme

Simple incrementing integer. Every rule create/update/delete bumps the global version. No semver needed — this is cache invalidation.

### Sync Endpoint

```
GET /api/v1/rules/sync?version=5
```

**Response when outdated:**

```json
{
  "version": 8,
  "updated_at": "2026-03-14T12:00:00Z",
  "rules": [
    {
      "id": "aws-secret-access-key",
      "format": "yaml",
      "content": "id: aws-secret-access-key\ninfo:\n  name: ..."
    },
    {
      "id": "private-key-pem",
      "format": "yara",
      "content": "rule private_key_pem {\n  meta:\n..."
    }
  ]
}
```

**Response when up-to-date:**

```json
{
  "version": 5,
  "status": "up_to_date"
}
```

Full ruleset download (not delta) — total payload is small (dozens of files, few KB each).

### Local Manifest (`~/.tatu/manifest.json`)

```json
{
  "version": 8,
  "api_url": "http://localhost:8000",
  "api_key": "tatu_xxxxx",
  "updated_at": "2026-03-14T12:00:00Z",
  "rule_count": 42
}
```

## tatu-hook CLI

### Installation & Setup

```bash
pip install tatu-hook
tatu-hook init --api-url http://tatu.company.com --api-key tatu_xxxxx
```

Creates `~/.tatu/manifest.json`, performs first sync, and generates Claude Code hooks config.

### Claude Code Configuration

Generated by `tatu-hook init` into project or user settings:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "tatu-hook --event session-start" }] }
    ],
    "PreToolUse": [
      { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook --event pre" }] }
    ],
    "PostToolUse": [
      { "matcher": ".*", "hooks": [{ "type": "command", "command": "tatu-hook --event post" }] }
    ]
  }
}
```

### Execution Flow (PreToolUse)

1. Claude Code pipes tool input JSON to stdin
2. `tatu-hook` loads cached rules from `~/.tatu/rules/` and `~/.tatu/yara/`
3. Filters rules where `hook_event == "PreToolUse"` and `matcher` matches the tool name
4. Evaluates regex patterns from YAML templates against the content
5. Evaluates YARA rules against the content (if yara-python installed)
6. For each matching rule, check its `mode`:
   - `mode: strict` + `action: block` → write deny to stderr, exit 2 (real block)
   - `mode: audit` + `action: block` → allow, but report as `status: audit_block`
   - `action: warn` (any mode) → write allow with warning context to stdout, exit 0
7. If no rules matched → write allow to stdout, exit 0
8. Fire-and-forget POST to `/api/v1/events` with the result (async, non-blocking)

### Dependencies

- **Core:** Zero external dependencies (regex engine only, like mintmcp)
- **Optional:** `yara-python` for YARA rule evaluation. If not installed, YARA rules are skipped with a warning.

## Dashboard Additions

### New "Rules" Page

- **Rules list:** Table with Name, Category, Severity, Action, Mode (audit/strict), Format (YAML/YARA), Source (built-in/custom), Status (enabled/disabled)
- **Rule editor:** Create/edit custom YAML templates or YARA rules with code editor. Validation on save (YAML parse, YARA compile)
- **Template gallery:** Browse built-in rules by category. One-click clone to create custom override.
- **Version history:** Current global version, last update timestamp, changed rules.

### New Backend Models

**Rule model:**
- `id` (string, unique — e.g., "aws-secret-access-key")
- `name` (string)
- `format` (enum: yaml, yara)
- `content` (text — full YAML or YARA source)
- `source` (enum: builtin, custom)
- `enabled` (boolean)
- `category` (string)
- `severity` (string)
- `mode` (enum: audit, strict — default: audit)
- `version_added` (int — global version when created/last updated)

**RuleVersion model:**
- Single row tracking the current global version counter
- Bumped on every rule create/update/delete

### New API Endpoints

- `GET /api/v1/rules` — list rules for dashboard (paginated, filterable)
- `POST /api/v1/rules` — create custom rule (bumps version)
- `PUT /api/v1/rules/{id}` — update custom rule (bumps version)
- `DELETE /api/v1/rules/{id}` — disable custom rule (bumps version)
- `GET /api/v1/rules/sync?version=X` — sync endpoint for tatu-hook (API key auth)
- `POST /api/v1/rules/import` — bulk import YAML/YARA files

### Built-in Rules Loading

On app startup, Tatu reads the `rules/` directory from the repo, upserts them into the database with `source=builtin`. The sync endpoint serves both built-in and custom rules from one source.

## SAST Rule Example

Template (`rules/sast/sql-injection-string-concat.yaml`):

```yaml
id: sast-sqli-string-concat
info:
  name: SQL Injection — String Concatenation in Query
  author: tatu-core
  severity: critical
  category: sast
  compliance:
    - SOC2 CC8.1
    - ISO 27001 A.14.2
  description: >
    Detects SQL queries built via string concatenation or f-strings
    with user-controlled variables. Use parameterized queries instead.
  tags:
    - sqli
    - python
    - cwe-89

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: block
  mode: audit

detect:
  type: regex
  patterns:
    - 'f["\'](?:SELECT|INSERT|UPDATE|DELETE)\s.+\{.*\}'
    - '(?:SELECT|INSERT|UPDATE|DELETE)\s.+%s'
    - '(?:SELECT|INSERT|UPDATE|DELETE)\s.*["'']\s*\+\s*\w+'
    - '(?:SELECT|INSERT|UPDATE|DELETE)\s.+\.format\s*\('

message: >
  SQL injection risk: query built with string interpolation (CWE-89).
  Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**How it works:** Claude generates code with `f"SELECT * FROM users WHERE id = {user_id}"`. The PreToolUse hook receives the file content, the regex matches, Claude Code gets a deny with the fix suggestion, and the event is reported to the dashboard.

**Limitations:** Regex-based SAST catches obvious patterns (string concat, f-strings, `.format()`) but not indirect injection across multiple lines. YARA helps with multi-condition matching. A future `type: ast` rule format could add real AST-based analysis.
