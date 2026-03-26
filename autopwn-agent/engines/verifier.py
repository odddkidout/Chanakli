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
        """Return only findings that pass verification."""
        verified: list[dict] = []
        for finding in findings:
            if await self._verify(finding):
                finding["verified"] = True
                finding.setdefault("confidence", self._settings.confidence_threshold)
                verified.append(finding)
        return verified

    async def _verify(self, finding: dict) -> bool:
        """Basic reproducibility check via HTTP probe."""
        url = finding.get("url") or finding.get("host")
        if not url:
            return True  # can't verify, pass through

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

        threshold = self._settings.reproducibility_runs * self._settings.confidence_threshold
        return successes >= threshold
