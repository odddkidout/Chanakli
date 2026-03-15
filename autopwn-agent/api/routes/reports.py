from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.routes.sessions import _sessions
from reports.generator import ReportGenerator

router = APIRouter()
_generator = ReportGenerator()


class ReportRequest(BaseModel):
    format: str = "markdown"


@router.post("/sessions/{session_id}/report")
async def generate_report(session_id: str, body: ReportRequest) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    content = _generator.generate(dict(session), fmt=body.format)
    return {"session_id": session_id, "format": body.format, "content": content}


@router.get("/sessions/{session_id}/chains")
async def get_chains(session_id: str) -> list:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.get("kill_chains", [])


@router.get("/sessions/{session_id}/attack-surface")
async def get_attack_surface(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.get("attack_surface", {})
