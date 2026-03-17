from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from datetime import datetime, timezone, timedelta

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.rule import Rule
from app.models.event import Event
from app.schemas.stats import OverviewStats, TimelineBucket
from app.schemas.rule_stats import RuleWithStats
from app.services.stats_service import get_overview_stats, get_timeline

router = APIRouter(
    prefix="/api/v1/overview",
    tags=["overview"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/stats", response_model=OverviewStats)
async def overview_stats(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    return await get_overview_stats(db, period)


@router.get("/timeline", response_model=list[TimelineBucket])
async def overview_timeline(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    return await get_timeline(db, period)


@router.get("/top-rules", response_model=list[RuleWithStats])
async def overview_top_rules(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))

    rules_result = await db.execute(select(Rule))
    rules = rules_result.scalars().all()

    result = []
    for rule in rules:
        stats = await db.execute(
            select(
                func.count(Event.id).label("triggers"),
                func.sum(case(
                    (Event.status.in_(["blocked", "audit_block"]), 1), else_=0
                )).label("blocks"),
            ).where(Event.hook_name == rule.name, Event.timestamp >= start)
        )
        row = stats.one()
        triggers = row.triggers or 0
        blocks = row.blocks or 0
        rate = f"{(blocks / triggers * 100):.1f}" if triggers > 0 else "0"

        result.append(RuleWithStats(
            id=rule.id, name=rule.name, category=rule.category,
            hook_event=rule.hook_event, matcher=rule.matcher,
            enabled=rule.enabled,
            compliance_mappings=rule.compliance_mappings or [],
            triggers=triggers, blocks=blocks, block_rate=rate,
        ))
    return result
