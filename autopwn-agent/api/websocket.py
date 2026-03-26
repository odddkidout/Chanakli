"""WebSocket helper for streaming pentest progress."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(session_id, []).append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket) -> None:
        conns = self._connections.get(session_id, [])
        if websocket in conns:
            conns.remove(websocket)

    async def broadcast(self, session_id: str, data: Any) -> None:
        payload = json.dumps(data, default=str)
        for ws in list(self._connections.get(session_id, [])):
            try:
                await ws.send_text(payload)
            except Exception:
                self.disconnect(session_id, ws)


manager = ConnectionManager()
