from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func, case, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event
from app.models.rule import Rule


def _period_to_delta(period: str) -> timedelta:
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    return mapping.get(period, timedelta(hours=24))


def _period_start(period: str) -> datetime:
    return datetime.now(timezone.utc) - _period_to_delta(period)


async def get_overview_stats(db: AsyncSession, period: str = "24h") -> dict:
    start = _period_start(period)

    # Get secret rule names from the rules table
    secret_rules_result = await db.execute(
        select(Rule.name).where(Rule.category == "secrets")
    )
    secret_rule_names = [row[0] for row in secret_rules_result.all()]

    # Build secrets_caught condition
    if secret_rule_names:
        secrets_condition = case(
            (Event.hook_name.in_(secret_rule_names), 1), else_=0
        )
    else:
        secrets_condition = case(
            (Event.hook_name == "__no_match__", 1), else_=0
        )

    result = await db.execute(
        select(
            func.count(Event.id).label("total_events"),
            func.sum(case(
                (Event.status.in_(["blocked", "audit_block"]), 1), else_=0
            )).label("total_blocks"),
            func.sum(secrets_condition).label("secrets_caught"),
        ).where(Event.timestamp >= start)
    )
    row = result.one()
    total_events = row.total_events or 0
    total_blocks = row.total_blocks or 0
    secrets_caught = row.secrets_caught or 0

    thirty_min_ago = datetime.now(timezone.utc) - timedelta(minutes=30)
    sessions_result = await db.execute(
        select(func.count(distinct(Event.session_id))).where(
            Event.timestamp >= thirty_min_ago
        )
    )
    active_sessions = sessions_result.scalar() or 0
    block_rate = (total_blocks / total_events * 100) if total_events > 0 else 0.0

    return {
        "total_events": total_events,
        "total_blocks": total_blocks,
        "active_sessions": active_sessions,
        "secrets_caught": secrets_caught,
        "block_rate": round(block_rate, 1),
    }


async def get_timeline(db: AsyncSession, period: str = "24h") -> list[dict]:
    start = _period_start(period)
    result = await db.execute(
        select(
            func.strftime("%H", Event.timestamp).label("hour"),
            func.count(Event.id).label("events"),
            func.sum(case((Event.status == "blocked", 1), else_=0)).label("blocks"),
        )
        .where(Event.timestamp >= start)
        .group_by("hour")
        .order_by("hour")
    )
    return [
        {"hour": row.hour, "events": row.events, "blocks": row.blocks or 0}
        for row in result.all()
    ]
