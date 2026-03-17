from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.models.event import Event
from app.schemas.event import EventResponse
from app.schemas.stats import PaginatedResponse
from app.services.event_service import get_alerts

router = APIRouter(
    prefix="/api/v1",
    tags=["alerts"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("/alerts/{alert_id}", response_model=EventResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == alert_id))
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return event


@router.get("/alerts", response_model=PaginatedResponse)
async def list_alerts(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    severity: str | None = Query(None),
    hook: str | None = Query(None),
    developer: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    return await get_alerts(db, period, severity, hook, developer, status, page, per_page)
