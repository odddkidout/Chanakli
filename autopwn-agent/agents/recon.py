"""Recon sub-agent — synthesises raw recon data into a structured attack surface."""
from __future__ import annotations

import json
import re

import httpx

from core.config import Settings


def _strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


class ReconAgent:
    """Uses the Auditor LLM to synthesise recon findings into a structured attack surface."""

    def __init__(self) -> None:
        self._settings = Settings()

    async def synthesise(self, raw_data: dict) -> dict:
        system = (
            "You are a senior penetration tester performing reconnaissance. "
            "Given raw recon data (subdomains, open ports, HTTP responses, technologies), "
            "produce a structured JSON attack surface with keys: "
            "subdomains (list), live_hosts (list), open_ports (dict host→list), "
            "technologies (list), interesting_endpoints (list), attack_vectors (list)."
        )
        user = f"Raw recon data:\n{json.dumps(raw_data, default=str)}"
        try:
            async with httpx.AsyncClient(
                base_url=self._settings.litellm_base_url, timeout=60
            ) as client:
                resp = await client.post(
                    "/chat/completions",
                    json={
                        "model": self._settings.auditor_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "temperature": 0.1,
                    },
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                return json.loads(_strip_fences(content))
        except Exception:
            return raw_data
