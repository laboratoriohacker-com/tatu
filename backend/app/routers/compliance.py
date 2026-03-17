from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.rule import Rule
from app.models.event import Event
from app.schemas.stats import ComplianceResponse, ComplianceFramework, ComplianceMapping

router = APIRouter(prefix="/api/v1", tags=["compliance"], dependencies=[Depends(require_dashboard_auth)])

FRAMEWORK_TOTALS = {
    "SOC2": 14,
    "LGPD": 8,
    "CPS234": 12,
    "ISO 27001": 18,
    "PCI DSS": 12,
    "NIST CSF": 10,
    "FedRAMP": 10,
    "DORA": 8,
    "GDPR": 8,
}


def _classify_control(control: str) -> str | None:
    for fw in FRAMEWORK_TOTALS:
        if control.startswith(fw) or (fw == "ISO 27001" and control.startswith("ISO")):
            return fw
    return None


@router.get("/compliance", response_model=ComplianceResponse)
async def get_compliance(
    period: str = Query("30d", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(days=30))

    rules_result = await db.execute(select(Rule).where(Rule.enabled.is_(True)))
    rules = rules_result.scalars().all()

    # Find rule names that have fired events in the period
    fired_result = await db.execute(
        select(Event.hook_name).where(Event.timestamp >= start).group_by(Event.hook_name)
    )
    fired_names = {row[0] for row in fired_result.all()}

    framework_coverage: dict[str, set[str]] = {fw: set() for fw in FRAMEWORK_TOTALS}
    framework_evidenced: dict[str, set[str]] = {fw: set() for fw in FRAMEWORK_TOTALS}
    mappings: list[ComplianceMapping] = []

    for rule in rules:
        rule_controls = rule.compliance_mappings or []
        has_evidence = rule.name in fired_names
        for control in rule_controls:
            fw = _classify_control(control)
            if fw:
                framework_coverage[fw].add(control)
                if has_evidence:
                    framework_evidenced[fw].add(control)
        if rule_controls:
            mappings.append(ComplianceMapping(hook=rule.name, maps=", ".join(rule_controls)))

    frameworks = []
    for fw, total in FRAMEWORK_TOTALS.items():
        covered = len(framework_coverage[fw])
        evidenced = len(framework_evidenced[fw])
        pct = min(round((covered / total) * 100), 100) if total > 0 else 0
        status = "compliant" if pct >= 90 else "partial" if pct >= 50 else "low"
        frameworks.append(ComplianceFramework(
            framework=fw, controls=total, covered=covered, evidenced=evidenced,
            status=status, percentage=pct,
        ))

    return ComplianceResponse(frameworks=frameworks, mappings=mappings)
