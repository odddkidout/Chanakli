from __future__ import annotations

from dataclasses import asdict
from typing import Optional

import structlog

from agents.recon import ReconAgent
from core.scope import Scope
from models.target import AttackSurface

logger = structlog.get_logger()


class ReconEngine:
    """Full 4-phase reconnaissance pipeline."""

    def __init__(
        self,
        scope: Scope,
        session_id: str,
        recon_agent: Optional[ReconAgent] = None,
        redis_client: Optional[object] = None,
    ):
        self.scope = scope
        self.session_id = session_id
        self.agent = recon_agent or ReconAgent(scope, session_id, redis_client=redis_client)

    def run(self, target: str) -> dict:
        """Execute full recon pipeline and return serializable attack surface dict."""
        logger.info("recon_engine_start", session_id=self.session_id, target=target)
        surface: AttackSurface = self.agent.build_attack_surface(target)
        logger.info(
            "recon_engine_complete",
            session_id=self.session_id,
            subdomains=len(surface.subdomains),
            live_hosts=len(surface.live_hosts),
            endpoints=len(surface.endpoints),
        )
        return asdict(surface)
