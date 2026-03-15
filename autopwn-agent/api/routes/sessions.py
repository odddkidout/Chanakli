from __future__ import annotations

import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from api.websocket import broadcast
from core.orchestrator import run_pentest

logger = structlog.get_logger()
router = APIRouter()

# In-memory session registry (replace with Redis in production)
_sessions: dict[str, dict] = {}


class StartSessionRequest(BaseModel):
    target: str
    scope: dict
    max_iterations: int = 50
    model_config: dict = {}


@router.post("/sessions")
async def start_session(
    body: StartSessionRequest, background_tasks: BackgroundTasks
) -> dict:
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "session_id": session_id,
        "target": body.target,
        "status": "queued",
        "findings": [],
        "kill_chains": [],
        "attack_surface": {},
        "failed_attempts": [],
    }

    async def _run():
        await broadcast(session_id, "node_start", {"node": "recon"})
        try:
            final_state = run_pentest(
                target=body.target,
                scope=body.scope,
                session_id=session_id,
                max_iterations=body.max_iterations,
            )
            _sessions[session_id].update(dict(final_state))
            await broadcast(session_id, "node_complete", {"node": "done"})
        except Exception as exc:
            _sessions[session_id]["status"] = "error"
            _sessions[session_id]["error"] = str(exc)
            await broadcast(session_id, "error", {"message": str(exc)})
            logger.error("session_run_error", session_id=session_id, error=str(exc))

    background_tasks.add_task(_run)
    logger.info("session_started", session_id=session_id, target=body.target)
    return {"session_id": session_id}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session_id,
        "target": session.get("target"),
        "status": session.get("status", "unknown"),
        "findings_count": len(session.get("findings", [])),
        "kill_chains_count": len(session.get("kill_chains", [])),
        "iteration_count": session.get("iteration_count", 0),
        "error": session.get("error"),
    }


@router.delete("/sessions/{session_id}")
async def stop_session(session_id: str) -> dict:
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    _sessions[session_id]["status"] = "stopped"
    logger.info("session_stopped", session_id=session_id)
    return {"session_id": session_id, "status": "stopped"}
