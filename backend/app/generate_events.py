"""Generate realistic sample events to populate the Tatu dashboard."""
import asyncio
import random
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func

from app.database import engine, async_session
from app.models import Base
from app.models.event import Event

DEVELOPERS = [
    "julio.melo",
    "ana.silva",
    "carlos.mendes",
    "marina.santos",
    "pedro.oliveira",
]

REPOSITORIES = [
    "tatush/backend",
    "tatush/frontend",
    "payments-api",
    "auth-service",
    "infra-config",
]

# Realistic event scenarios per hook
SCENARIOS: list[dict] = [
    {
        "hook_name": "Destructive Command Blocker",
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "Blocked: rm -rf / — destructive command detected"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: DROP TABLE users — SQL destructive operation"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: git push --force origin main — force push to protected branch"},
            {"severity": "warning", "status": "warning", "message": "Warning: chmod 777 detected on sensitive directory"},
            {"severity": "info", "status": "allowed", "message": "Allowed: git reset --soft HEAD~1 — non-destructive reset"},
        ],
    },
    {
        "hook_name": "Secrets Leak Prevention",
        "hook_event": "PreToolUse",
        "tool_name": "Write",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "Blocked: AWS_SECRET_ACCESS_KEY found in config.py"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: hardcoded database password in settings.py"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: GitHub personal access token in .env committed"},
            {"severity": "warning", "status": "warning", "message": "Warning: possible API key pattern detected in utils.py"},
            {"severity": "info", "status": "clean", "message": "Scan clean: no secrets detected in deployment.yaml"},
        ],
    },
    {
        "hook_name": "LGPD PII Detector",
        "hook_event": "PreToolUse",
        "tool_name": "Write",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "Blocked: CPF number (XXX.XXX.XXX-XX) found in log output"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: Brazilian phone number exposed in API response"},
            {"severity": "warning", "status": "warning", "message": "Warning: email address pattern in debug log — possible PII"},
            {"severity": "info", "status": "clean", "message": "Scan clean: no PII detected in report_generator.py"},
        ],
    },
    {
        "hook_name": "Auto SAST Scanner",
        "hook_event": "PostToolUse",
        "tool_name": "Edit",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "SAST: SQL injection vulnerability in query builder (CWE-89)"},
            {"severity": "critical", "status": "blocked", "message": "SAST: XSS vulnerability — unescaped user input in template (CWE-79)"},
            {"severity": "warning", "status": "warning", "message": "SAST: insecure deserialization in data_loader.py (CWE-502)"},
            {"severity": "warning", "status": "warning", "message": "SAST: hardcoded credentials detected (CWE-798)"},
            {"severity": "info", "status": "clean", "message": "SAST scan passed: no vulnerabilities in auth_middleware.py"},
        ],
    },
    {
        "hook_name": "Dependency Vuln Check",
        "hook_event": "PostToolUse",
        "tool_name": "Bash",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "CVE-2024-3094: critical vulnerability in xz-utils 5.6.0"},
            {"severity": "warning", "status": "warning", "message": "CVE-2024-22195: Jinja2 XSS — upgrade to 3.1.3+"},
            {"severity": "warning", "status": "warning", "message": "3 moderate vulnerabilities found in npm dependencies"},
            {"severity": "info", "status": "clean", "message": "All 142 dependencies scanned — no known vulnerabilities"},
        ],
    },
    {
        "hook_name": "Network Scope Enforcer",
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "Blocked: curl to external IP 185.234.xx.xx — not in allowlist"},
            {"severity": "warning", "status": "warning", "message": "Warning: DNS lookup for unknown domain suspicious-cdn.com"},
            {"severity": "info", "status": "allowed", "message": "Allowed: curl to api.github.com — in approved domains"},
        ],
    },
    {
        "hook_name": "Protected File Guardian",
        "hook_event": "PreToolUse",
        "tool_name": "Edit",
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "Blocked: attempted modification of /etc/shadow"},
            {"severity": "critical", "status": "blocked", "message": "Blocked: write to .github/workflows/deploy.yml — protected CI config"},
            {"severity": "warning", "status": "warning", "message": "Warning: modification to Dockerfile in production directory"},
            {"severity": "info", "status": "allowed", "message": "Allowed: edit to src/components/Button.tsx — not protected"},
        ],
    },
    {
        "hook_name": "Session Audit Logger",
        "hook_event": "PostToolUse",
        "tool_name": "Bash",
        "templates": [
            {"severity": "info", "status": "clean", "message": "Audit: session activity logged — 12 tool calls recorded"},
            {"severity": "info", "status": "clean", "message": "Audit: session transcript archived to compliance store"},
            {"severity": "info", "status": "clean", "message": "Audit: developer session duration 45m — within policy limits"},
        ],
    },
    {
        "hook_name": "Change Classification",
        "hook_event": "PostToolUse",
        "tool_name": "Write",
        "templates": [
            {"severity": "warning", "status": "warning", "message": "Change classified as HIGH RISK: database migration modifies schema"},
            {"severity": "info", "status": "clean", "message": "Change classified as LOW RISK: documentation update"},
            {"severity": "info", "status": "clean", "message": "Change classified as MEDIUM RISK: new API endpoint added"},
        ],
    },
    {
        "hook_name": "Security Alert Notifier",
        "hook_event": "Notification",
        "tool_name": None,
        "templates": [
            {"severity": "critical", "status": "blocked", "message": "ALERT sent to #security-ops: multiple secrets blocked in session"},
            {"severity": "warning", "status": "warning", "message": "ALERT sent to dev lead: 3 SAST findings in single commit"},
            {"severity": "info", "status": "clean", "message": "Daily security summary sent: 0 critical, 2 warnings, 48 clean"},
        ],
    },
    {
        "hook_name": "Env Hardening Validator",
        "hook_event": "SessionStart",
        "tool_name": None,
        "templates": [
            {"severity": "warning", "status": "warning", "message": "Environment check: .env file has world-readable permissions"},
            {"severity": "info", "status": "clean", "message": "Environment hardened: all security hooks enabled, MFA verified"},
            {"severity": "info", "status": "clean", "message": "Environment check passed: SSH agent forwarding disabled"},
        ],
    },
    {
        "hook_name": "Threat Intel Injector",
        "hook_event": "SessionStart",
        "tool_name": None,
        "templates": [
            {"severity": "info", "status": "clean", "message": "Threat intel updated: 3 new IOCs loaded for dependency scanning"},
            {"severity": "warning", "status": "warning", "message": "Threat advisory: active campaign targeting Python packages"},
        ],
    },
]

# Weight: more info/clean events than criticals (realistic distribution)
SEVERITY_WEIGHTS = {"critical": 0.1, "warning": 0.25, "info": 0.65}


async def generate_events(count: int = 200, hours: int = 24):
    """Generate sample events spread over the last N hours."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        # Check if events already exist
        result = await session.execute(select(func.count(Event.id)))
        existing = result.scalar() or 0
        if existing > 0:
            print(f"Database already has {existing} events. Adding {count} more.")

        now = datetime.now(timezone.utc)
        events = []

        for _ in range(count):
            scenario = random.choice(SCENARIOS)
            template = random.choice(scenario["templates"])
            ts = now - timedelta(
                hours=random.uniform(0, hours),
                minutes=random.uniform(0, 60),
            )

            event = Event(
                id=uuid.uuid4(),
                timestamp=ts,
                hook_name=scenario["hook_name"],
                hook_event=scenario["hook_event"],
                severity=template["severity"],
                status=template["status"],
                message=template["message"],
                developer=random.choice(DEVELOPERS),
                repository=random.choice(REPOSITORIES),
                session_id=str(uuid.uuid4())[:8],
                tool_name=scenario["tool_name"],
                metadata_={},
            )
            events.append(event)

        session.add_all(events)
        await session.commit()
        print(f"Generated {count} sample events over the last {hours}h.")

        # Print summary
        blocks = sum(1 for e in events if e.status == "blocked")
        warnings = sum(1 for e in events if e.status == "warning")
        clean = sum(1 for e in events if e.status in ("clean", "allowed"))
        print(f"  Blocked: {blocks} | Warnings: {warnings} | Clean/Allowed: {clean}")


if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
    asyncio.run(generate_events(count, hours))
