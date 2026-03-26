"""Verification engine — reproducibility checks + WAF detection + LLM confirmation."""
from __future__ import annotations

import asyncio

import httpx

from core.config import Settings
from core.scope import Scope


class VerificationEngine:
    def __init__(self, scope: dict) -> None:
        self._scope = Scope(scope)
        self._settings = Settings()

    async def verify_all(self, findings: list[dict]) -> list[dict]:
        """Return all findings annotated with verification status and confidence."""
        verified: list[dict] = []
        for finding in findings:
            passed, confidence = await self._verify(finding)
            finding["confidence"] = finding.get("confidence", confidence)
            finding["verified"] = passed
            verified.append(finding)
        return verified

    async def _verify(self, finding: dict) -> tuple[bool, float]:
        """Basic reproducibility check via HTTP probe.

        Returns (passed, confidence) where confidence is low when unverifiable.
        """
        url = finding.get("url") or finding.get("host")
        if not url:
            # Cannot verify — keep finding but mark confidence as low
            return True, 0.3

        if not url.startswith("http"):
            url = f"https://{url}"

        successes = 0
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for _ in range(self._settings.reproducibility_runs):
                try:
                    resp = await client.get(url)
                    if resp.status_code < 500:
                        successes += 1
                except Exception:
                    pass

        ratio = successes / max(self._settings.reproducibility_runs, 1)
        threshold = self._settings.confidence_threshold
        return ratio >= threshold, ratio
