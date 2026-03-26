"""Vulnerability scanner — runs nuclei across live hosts."""
from __future__ import annotations

import asyncio
from typing import Any

from core.config import Settings
from core.scope import Scope


class VulnerabilityScanner:
    def __init__(self, scope: dict) -> None:
        self._scope = Scope(scope)
        self._settings = Settings()

    async def scan(self, live_hosts: list[str]) -> list[dict]:
        """Run nuclei against each live host and aggregate findings."""
        from tools.wrappers.nuclei_wrapper import NucleiWrapper
        from tools.safe_executor import SafeExecutor

        wrapper = NucleiWrapper()
        if not wrapper.is_available():
            return []

        safe = SafeExecutor(scope=self._scope)
        findings: list[dict] = []

        for host in live_hosts:
            command = ["nuclei", "-u", f"https://{host}", "-json", "-silent"]
            try:
                self._scope.validate_command(command)
                result = await safe.run(command)
                host_findings = wrapper.parse_output(result["stdout"])
                if isinstance(host_findings, list):
                    findings.extend(host_findings)
                elif host_findings:
                    findings.append(host_findings)
            except Exception:
                pass

        return findings
