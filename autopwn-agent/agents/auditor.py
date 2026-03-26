"""Auditor agent — planning, analysis, and reflection using the Auditor LLM."""
from __future__ import annotations

import json
import re
import asyncio
from typing import Any

import httpx

from core.config import Settings


def _strip_fences(text: str) -> str:
    """Remove markdown JSON code fences."""
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


class AuditorAgent:
    """Calls the Auditor LLM (GLM-5 / GPT-4o) for strategic decisions."""

    def __init__(self) -> None:
        self._settings = Settings()

    async def _call_llm(self, system: str, user: str, retries: int = 3) -> str:
        payload = {
            "model": self._settings.auditor_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }
        delay = 1.0
        last_exc: Exception | None = None
        async with httpx.AsyncClient(base_url=self._settings.litellm_base_url, timeout=60) as client:
            for attempt in range(retries):
                try:
                    resp = await client.post("/chat/completions", json=payload)
                    resp.raise_for_status()
                    return resp.json()["choices"][0]["message"]["content"]
                except Exception as exc:
                    last_exc = exc
                    await asyncio.sleep(delay)
                    delay *= 2
        raise RuntimeError(f"LLM call failed after {retries} attempts: {last_exc}")

    async def plan(
        self,
        target: str,
        attack_surface: dict,
        failed_attempts: list[dict],
    ) -> list[dict]:
        system = (
            "You are a senior penetration tester. Given an attack surface and previously "
            "failed attempts, produce a JSON array of attack tasks ordered by priority. "
            "Each task must have: technique (str), description (str), tool (str), priority (1-10)."
        )
        user = (
            f"Target: {target}\n"
            f"Attack surface: {json.dumps(attack_surface, default=str)}\n"
            f"Failed attempts: {json.dumps(failed_attempts, default=str)}\n\n"
            "Return ONLY a JSON array of attack tasks."
        )
        try:
            raw = await self._call_llm(system, user)
            return json.loads(_strip_fences(raw))
        except Exception:
            return [
                {
                    "technique": "web_scan",
                    "description": f"Run a basic web vulnerability scan against {target}",
                    "tool": "nuclei",
                    "priority": 9,
                }
            ]

    async def reflect(
        self,
        findings: list[dict],
        failed_attempts: list[dict],
        iteration: int,
        max_iterations: int,
    ) -> tuple[str, bool]:
        if iteration >= max_iterations:
            return "Max iterations reached — finalising session.", False

        system = (
            "You are a senior penetration tester reviewing a completed attack iteration. "
            "Decide whether another iteration would likely yield new findings. "
            "Reply with JSON: {\"note\": \"<observation>\", \"continue\": true|false}"
        )
        user = (
            f"Iteration {iteration}/{max_iterations}\n"
            f"Findings so far: {len(findings)}\n"
            f"Failed attempts: {len(failed_attempts)}\n"
            f"Findings summary: {json.dumps([f.get('title','?') for f in findings])}\n\n"
            "Should we run another iteration?"
        )
        try:
            raw = await self._call_llm(system, user)
            data = json.loads(_strip_fences(raw))
            return data.get("note", ""), bool(data.get("continue", False))
        except Exception:
            return "Reflection failed — stopping.", False

    async def enrich_finding(self, finding: dict) -> dict:
        system = (
            "You are a security analyst. Enrich the given finding with: "
            "severity (critical/high/medium/low/info), cve (if applicable), "
            "remediation advice. Return JSON with those fields added."
        )
        user = json.dumps(finding, default=str)
        try:
            raw = await self._call_llm(system, user)
            enriched = json.loads(_strip_fences(raw))
            finding.update(enriched)
        except Exception:
            pass
        return finding
