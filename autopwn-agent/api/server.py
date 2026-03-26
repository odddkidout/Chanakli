"""FastAPI application — AutoPwn Agent control plane."""
from __future__ import annotations

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from api.routes import sessions, findings, reports
from api.websocket import manager

app = FastAPI(
    title="AutoPwn Agent",
    description="Autonomous penetration testing AI system",
    version="1.0.0",
)

app.include_router(sessions.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/sessions/{session_id}/stream")
async def websocket_stream(websocket: WebSocket, session_id: str) -> None:
    await manager.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
