import pytest
from unittest.mock import AsyncMock
from app.services.websocket_manager import WebSocketManager


@pytest.mark.asyncio
async def test_connect_and_broadcast():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    await manager.connect(ws)
    assert len(manager.active_connections) == 1
    await manager.broadcast({"type": "event", "data": "test"})
    ws.send_json.assert_called_once_with({"type": "event", "data": "test"})


@pytest.mark.asyncio
async def test_disconnect():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    await manager.connect(ws)
    manager.disconnect(ws)
    assert len(manager.active_connections) == 0


@pytest.mark.asyncio
async def test_broadcast_removes_dead_connections():
    manager = WebSocketManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock(side_effect=Exception("connection closed"))
    await manager.connect(ws)
    await manager.broadcast({"type": "test"})
    assert len(manager.active_connections) == 0
