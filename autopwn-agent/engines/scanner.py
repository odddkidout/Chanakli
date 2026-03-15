from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

import structlog

from agents.auditor import AuditorAgent
from core.scope import Scope
from models.finding import Finding
from models.task import AttackTask
from tools.safe_executor import SafeExecutor
from tools.tool_registry import ToolRegistry

logger = structlog.get_logger()


class VulnerabilityScanner:
    """LLM-augmented vulnerability scanner that runs targeted nuclei / manual checks."""

    def __init__(
        self,
        scope: Scope,
        session_id: str,
        auditor: Optional[AuditorAgent] = None,
        redis_client: Optional[object] = None,
    ):
        self.scope = scope
        self.session_id = session_id
        self.auditor = auditor or AuditorAgent()
        self.executor = SafeExecutor(scope, session_id, redis_client)
        self.registry = ToolRegistry()

    def scan(self, attack_surface: dict) -> list[Finding]:
        """Run vulnerability scanning across all live hosts."""
        findings: list[Finding] = []
        live_hosts = attack_surface.get("live_hosts", [])

        nuclei_wrapper = self.registry.get("nuclei")
        if not (nuclei_wrapper and nuclei_wrapper.is_available()):
            logger.warning("nuclei_not_available", session_id=self.session_id)
            return findings

        for host in live_hosts[:20]:  # cap scan targets
            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title=f"Nuclei scan: {host}",
                target_endpoint=host,
                vulnerability_hypothesis="general vulnerability scan",
                attack_type="network",
                tool="nuclei",
                tool_flags="-tags cve,misconfiguration,exposure -severity medium,high,critical",
            )
            result = self.executor.run(nuclei_wrapper.build_command(task), timeout=120)
            for raw in nuclei_wrapper.parse_output(result.stdout, result.stderr):
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        session_id=self.session_id,
                        task_id=task.task_id,
                        type=raw.get("type", "nuclei"),
                        title=raw.get("title", ""),
                        endpoint=raw.get("endpoint", host),
                        parameter=None,
                        payload=None,
                        evidence=str(raw.get("extracted_results", ""))[:2048],
                        severity=raw.get("severity", "info"),
                        confidence=0.8,
                        requires_auth=False,
                        cvss_score=None,
                        cwe_id=None,
                        discovered_at=datetime.now(timezone.utc),
                        tool_used="nuclei",
                        raw_output=str(raw),
                    )
                )

        logger.info(
            "scanner_complete",
            session_id=self.session_id,
            findings_count=len(findings),
        )
        return findings
