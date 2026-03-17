from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, distinct
from datetime import datetime, timezone, timedelta

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.event import Event
from app.schemas.stats import DeveloperStats

router = APIRouter(prefix="/api/v1", tags=["developers"], dependencies=[Depends(require_dashboard_auth)])


@router.get("/developers", response_model=list[DeveloperStats])
async def list_developers(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    start = datetime.now(timezone.utc) - mapping.get(period, timedelta(hours=24))

    result = await db.execute(
        select(
            Event.developer,
            func.count(distinct(Event.session_id)).label("sessions"),
            func.sum(case((Event.status == "blocked", 1), else_=0)).label("blocks"),
        )
        .where(Event.timestamp >= start)
        .group_by(Event.developer)
        .order_by(func.sum(case((Event.status == "blocked", 1), else_=0)).desc())
    )

    return [
        DeveloperStats(
            name=row.developer,
            sessions=row.sessions,
            blocks=row.blocks or 0,
            risk="high" if (row.blocks or 0) > 5 else "low",
        )
        for row in result.all()
    ]
