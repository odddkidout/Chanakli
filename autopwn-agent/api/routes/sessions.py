"""Session management routes."""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from core.orchestrator import run_pentest

router = APIRouter(prefix="/sessions", tags=["sessions"])

_sessions: dict[str, dict] = {}


class SessionRequest(BaseModel):
    target: str
    scope: dict = {
        "domains": ["pigi.in", "*.pigi.in"],
        "ports": [80, 443],
        "paths": ["/"],
        "cidrs": [],
    }
    max_iterations: int = 10


@router.post("", status_code=201)
async def create_session(req: SessionRequest, background_tasks: BackgroundTasks) -> dict:
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {"status": "started", "target": req.target, "result": None}

    async def _run():
        try:
            result = await run_pentest(
                session_id=session_id,
                target=req.target,
                scope=req.scope,
                max_iterations=req.max_iterations,
            )
            _sessions[session_id] = {"status": "done", "target": req.target, "result": result}
        except Exception as exc:
            _sessions[session_id] = {"status": "error", "target": req.target, "error": str(exc)}

    background_tasks.add_task(_run)
    return {"session_id": session_id, "status": "started"}


@router.get("/{session_id}")
async def get_session(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.delete("/{session_id}", status_code=204)
async def delete_session(session_id: str) -> None:
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    del _sessions[session_id]
