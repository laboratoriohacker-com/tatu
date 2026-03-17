import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_dashboard_auth
from app.database import get_db
from app.services.event_service import get_alerts

router = APIRouter(prefix="/api/v1", tags=["audit"], dependencies=[Depends(require_dashboard_auth)])

STATUS_LABELS = {"blocked": "DENY", "warning": "WARN", "allowed": "ALLOW", "clean": "PASS"}


@router.get("/audit")
async def audit_log(
    period: str = Query("24h", pattern="^(24h|7d|30d)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    format: str | None = Query(None, pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
):
    if format in ("csv", "json"):
        data = await get_alerts(db, period, page=1, per_page=10000)
    else:
        data = await get_alerts(db, period, page=page, per_page=per_page)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "developer", "hook", "event_detail", "result"])
        for event in data["items"]:
            writer.writerow([
                event["timestamp"],
                event["developer"],
                event["hook_name"],
                event["message"],
                STATUS_LABELS.get(event["status"], event["status"]),
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=tatu-audit.csv"},
        )

    if format == "json":
        return [
            {
                "timestamp": event["timestamp"],
                "developer": event["developer"],
                "hook": event["hook_name"],
                "event_detail": event["message"],
                "result": STATUS_LABELS.get(event["status"], event["status"]),
            }
            for event in data["items"]
        ]

    return data
