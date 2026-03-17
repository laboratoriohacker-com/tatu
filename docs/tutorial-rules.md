# Rule Writing Tutorial

This guide explains how to create, edit, and manage security rules in Tatu.

## Rule Formats

Tatu supports two rule formats:

- **YAML templates** — Regex-based detection for text content (secrets, PII, commands)
- **YARA rules** — Multi-condition pattern matching for complex detection

## YAML Template Structure

```yaml
id: unique-rule-id
info:
  name: Human Readable Name
  author: your-name
  severity: critical    # critical | warning | info
  category: secrets     # secrets | pii | destructive | sast | files
  compliance:
    - SOC2 CC6.1
    - ISO 27001 A.9.4
  description: What this rule detects and why it matters.
  tags:
    - aws
    - cloud

hook:
  event: PreToolUse     # PreToolUse | PostToolUse
  matcher: Write|Edit   # Regex matching tool names
  action: block         # block | warn | log
  mode: audit           # audit (default) | strict

detect:
  type: regex
  patterns:
    - 'regex pattern 1'
    - 'regex pattern 2'

message: "Message shown when rule matches"
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique identifier (kebab-case) |
| `info.name` | Yes | Display name in the dashboard |
| `info.severity` | Yes | `critical`, `warning`, or `info` |
| `info.category` | Yes | Groups rules in the dashboard |
| `info.compliance` | No | Maps to compliance framework controls |
| `hook.event` | Yes | `PreToolUse` (before action) or `PostToolUse` (after) |
| `hook.matcher` | Yes | Regex for tool names: `Write`, `Edit`, `Bash`, `Read`, `.*` |
| `hook.action` | Yes | `block` (deny), `warn` (allow with warning), `log` (silent) |
| `hook.mode` | No | `audit` (default, log only) or `strict` (enforce) |
| `detect.patterns` | Yes | List of regex patterns to match against content |
| `message` | Yes | Shown to the developer when the rule triggers |

### Mode Behavior

| Mode | action: block | action: warn |
|---|---|---|
| **audit** | Allows, reports `audit_block` to dashboard | Allows with warning |
| **strict** | Denies the Claude Code operation | Allows with warning |

**Start with `audit`** for every new rule. Monitor matches in the dashboard, then switch to `strict` when confident.

## Writing Your First Rule

### Example: Detect hardcoded database URLs

```yaml
id: hardcoded-db-url
info:
  name: Hardcoded Database URL
  author: your-team
  severity: warning
  category: secrets
  compliance:
    - SOC2 CC6.1
  description: Detects database connection strings with embedded credentials.
  tags:
    - database
    - credentials

hook:
  event: PreToolUse
  matcher: Write|Edit
  action: warn
  mode: audit

detect:
  type: regex
  patterns:
    - '(?:postgres|mysql|mongodb)://\w+:\w+@'

message: "Database URL with embedded credentials detected. Use environment variables instead."
```

### Where to put it

**Built-in rules (for the team):**

Add the file to `rules/<category>/` in the repository:

```
rules/secrets/hardcoded-db-url.yaml
```

Rules in this directory are loaded automatically on app startup.

**Custom rules (via dashboard):**

1. Go to the **Rules** page
2. Click any built-in rule to view it
3. Click **Clone to Custom** to make an editable copy
4. Or create new rules via the API:

```bash
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Cookie: tatu_session=..." \
  -H "Content-Type: application/json" \
  -d '{
    "id": "custom-db-url",
    "name": "Hardcoded Database URL",
    "format": "yaml",
    "content": "id: custom-db-url\ninfo:\n  name: ...",
    "category": "secrets",
    "severity": "warning",
    "mode": "audit",
    "action": "warn",
    "hook_event": "PreToolUse",
    "matcher": "Write|Edit"
  }'
```

## Regex Tips for Rules

### Match tool content, not filenames

The `matcher` field filters by **tool name** (Write, Edit, Bash, Read). The `patterns` match against the **content** being written or the command being executed.

### Common patterns

```yaml
# Match AWS access key IDs
- '\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b'

# Match Brazilian CPF numbers (XXX.XXX.XXX-XX)
- '\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'

# Match destructive git commands
- '\bgit\s+push\s+.*--force'

# Match SQL injection via f-strings (Python)
- 'f["\'']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s.+\{.*\}'

# Match unsafe DOM manipulation (XSS)
- '\.innerHTML\s*='
```

### Avoiding false positives

- Use `\b` word boundaries to avoid partial matches
- Use `(?i)` for case-insensitive matching
- Test patterns against real code before deploying
- Start with `mode: audit` to observe matches without blocking

## YARA Rules

For complex, multi-condition detection:

```yara
rule private_key_pem {
  meta:
    id = "yara-private-key"
    severity = "critical"
    category = "secrets"
    action = "block"
    mode = "audit"
    hook_event = "PreToolUse"
    matcher = "Write|Edit|Read"
  strings:
    $begin = "-----BEGIN" ascii
    $private = "PRIVATE KEY-----" ascii
    $end = "-----END" ascii
  condition:
    $begin and $private and $end
}
```

YARA rules require `yara-python` installed on the developer's machine:

```bash
pip install "tatu-hook[yara]"
```

If `yara-python` is not installed, YARA rules are silently skipped.

## Rule Lifecycle

### Built-in rules

1. Stored in `rules/` directory in the repo
2. Loaded into the database on app startup
3. Source = `builtin`, content is read-only in the dashboard
4. Can be cloned to custom for editing
5. If a custom override is deleted, the built-in restores on next restart

### Custom rules

1. Created via the dashboard or API
2. Source = `custom`, fully editable
3. Override built-in rules with the same id
4. Synced to developer machines via `tatu-hook` on SessionStart

### Version sync

Every rule create/update/delete bumps a global version counter. When a developer starts a Claude Code session, `tatu-hook` checks its local version against the server and downloads the full ruleset if outdated.

## Compliance Mapping

Rules can map to compliance framework controls:

```yaml
info:
  compliance:
    - SOC2 CC6.1        # Logical and Physical Access Controls
    - SOC2 CC8.1        # Change Management
    - LGPD Art. 37      # Records of Processing Activities
    - LGPD Art. 46      # Security Measures
    - CPS234 Op. Risk   # Operational Risk Management
    - ISO 27001 A.9.4   # System and Application Access Control
    - ISO 27001 A.14.2  # Security in Development Processes
```

These mappings are used by the Compliance dashboard page to calculate coverage percentages per framework.
