"""Report generation routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.routes.sessions import _sessions

router = APIRouter(prefix="/sessions", tags=["reports"])


class ReportRequest(BaseModel):
    format: str = "markdown"


@router.post("/{session_id}/report")
async def generate_report(session_id: str, req: ReportRequest) -> dict:
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    from reports.generator import ReportGenerator

    gen = ReportGenerator()
    result = session.get("result") or {}
    report = gen.generate(
        session_id=session_id,
        target=session.get("target", ""),
        findings=result.get("findings", []),
        kill_chains=result.get("kill_chains", []),
        attack_surface=result.get("attack_surface", {}),
        fmt=req.format,
    )
    return {"report": report, "format": req.format}
