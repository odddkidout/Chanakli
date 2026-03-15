from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.sessions import router as sessions_router
from api.routes.findings import router as findings_router
from api.routes.reports import router as reports_router
from api.websocket import router as ws_router

logger = structlog.get_logger()

app = FastAPI(
    title="AutoPwn Agent",
    description="Production-grade autonomous penetration testing AI system",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sessions_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(ws_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
