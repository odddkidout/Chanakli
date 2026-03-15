from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.routes.sessions import _sessions

router = APIRouter()


@router.get("/sessions/{session_id}/findings")
async def get_findings(session_id: str) -> list:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.get("findings", [])
