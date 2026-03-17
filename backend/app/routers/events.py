import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_api_key, require_ws_auth
from app.database import get_db
from app.models.api_key import ApiKey
from app.models.event import Event
from app.schemas.event import EventCreate, EventResponse
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.post("/events", response_model=EventResponse, status_code=201)
async def ingest_event(
    body: EventCreate,
    api_key: ApiKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hook_name=body.hook_name,
        hook_event=body.hook_event,
        severity=body.severity,
        status=body.status,
        message=body.message,
        developer=body.developer,
        repository=body.repository,
        session_id=body.session_id,
        tool_name=body.tool_name,
        metadata_=body.metadata,
    )
    db.add(event)
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    await ws_manager.broadcast({
        "type": "new_event",
        "event": {
            "id": str(event.id),
            "timestamp": event.timestamp.isoformat(),
            "hook_name": event.hook_name,
            "hook_event": event.hook_event,
            "severity": event.severity,
            "status": event.status,
            "message": event.message,
            "developer": event.developer,
            "repository": event.repository,
            "session_id": event.session_id,
            "tool_name": event.tool_name,
        },
    })
    return event


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await require_ws_auth(websocket)
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
