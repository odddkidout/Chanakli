"""Findings query routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.routes.sessions import _sessions

router = APIRouter(prefix="/sessions", tags=["findings"])


@router.get("/{session_id}/findings")
async def get_findings(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    result = session.get("result") or {}
    return {"findings": result.get("findings", []), "kill_chains": result.get("kill_chains", [])}


@router.get("/{session_id}/attack-surface")
async def get_attack_surface(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    result = session.get("result") or {}
    return {"attack_surface": result.get("attack_surface", {})}
