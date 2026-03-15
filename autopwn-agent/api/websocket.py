from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Optional

import structlog
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

logger = structlog.get_logger()

router = APIRouter()

# In-memory store for active WebSocket connections per session
_ws_connections: dict[str, list[WebSocket]] = {}


async def broadcast(session_id: str, event: str, data: Any) -> None:
    """Broadcast a message to all WebSocket subscribers of a session."""
    connections = _ws_connections.get(session_id, [])
    message = json.dumps({"event": event, "data": data}, default=str)
    dead: list[WebSocket] = []
    for ws in connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)


@router.websocket("/sessions/{session_id}/stream")
async def websocket_endpoint(websocket: WebSocket, session_id: str) -> None:
    """Real-time progress streaming for a pentest session."""
    await websocket.accept()
    _ws_connections.setdefault(session_id, []).append(websocket)
    logger.info("ws_connected", session_id=session_id)
    try:
        while True:
            # Keep connection alive; client messages are ignored
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        _ws_connections.get(session_id, []).remove(websocket)
        logger.info("ws_disconnected", session_id=session_id)
    except Exception as exc:
        logger.warning("ws_error", session_id=session_id, error=str(exc))
        try:
            _ws_connections.get(session_id, []).remove(websocket)
        except ValueError:
            pass
