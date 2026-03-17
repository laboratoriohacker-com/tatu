from datetime import datetime, timezone, timedelta
import math
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event


def _period_start(period: str) -> datetime:
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    return datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))


async def get_alerts(
    db: AsyncSession,
    period: str = "24h",
    severity: str | None = None,
    hook: str | None = None,
    developer: str | None = None,
    status: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    per_page = min(per_page, 200)
    start = _period_start(period)

    query = select(Event).where(Event.timestamp >= start)
    count_query = select(func.count(Event.id)).where(Event.timestamp >= start)

    if severity:
        query = query.where(Event.severity == severity)
        count_query = count_query.where(Event.severity == severity)
    if hook:
        query = query.where(Event.hook_name == hook)
        count_query = count_query.where(Event.hook_name == hook)
    if developer:
        query = query.where(Event.developer == developer)
        count_query = count_query.where(Event.developer == developer)
    if status:
        query = query.where(Event.status == status)
        count_query = count_query.where(Event.status == status)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(Event.timestamp.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    items = result.scalars().all()

    serialized_items = [
        {
            "id": str(e.id),
            "timestamp": e.timestamp.isoformat(),
            "hook_name": e.hook_name,
            "hook_event": e.hook_event,
            "severity": e.severity,
            "status": e.status,
            "message": e.message,
            "developer": e.developer,
            "repository": e.repository,
            "session_id": e.session_id,
            "tool_name": e.tool_name,
            "metadata_": e.metadata_,
        }
        for e in items
    ]

    return {
        "items": serialized_items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": math.ceil(total / per_page) if per_page > 0 else 0,
    }
