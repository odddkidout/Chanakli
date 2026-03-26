"""Recon engine — 4-phase pipeline: passive → active → deep crawl → LLM synthesis."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from core.config import Settings


class ReconEngine:
    def __init__(self, target: str, scope: dict) -> None:
        self._target = target
        self._scope = scope
        self._settings = Settings()

    # ------------------------------------------------------------------
    # Phase 1: Passive recon
    # ------------------------------------------------------------------

    async def _passive_recon(self) -> dict:
        """Collect subdomains via crt.sh (best-effort)."""
        subdomains: list[str] = [self._target]
        try:
            async with httpx.AsyncClient(timeout=self._settings.request_timeout) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%25.{self._target}&output=json"
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(self._target) and sub not in subdomains:
                                subdomains.append(sub)
        except Exception:
            pass
        return {"subdomains": subdomains}

    # ------------------------------------------------------------------
    # Phase 2: Active recon
    # ------------------------------------------------------------------

    async def _active_recon(self, subdomains: list[str]) -> dict:
        """Probe each subdomain with a HEAD request."""
        live_hosts: list[str] = []
        async with httpx.AsyncClient(
            timeout=self._settings.request_timeout, follow_redirects=True
        ) as client:
            tasks = [self._probe(client, host) for host in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        for host, result in zip(subdomains, results):
            if isinstance(result, dict) and result.get("live"):
                live_hosts.append(host)
        return {"live_hosts": live_hosts}

    async def _probe(self, client: httpx.AsyncClient, host: str) -> dict:
        for scheme in ("https", "http"):
            try:
                resp = await client.head(f"{scheme}://{host}", timeout=10)
                if resp.status_code < 600:
                    return {"live": True, "status": resp.status_code, "scheme": scheme}
            except Exception:
                continue
        return {"live": False}

    # ------------------------------------------------------------------
    # Phase 3: Deep crawl (basic endpoint discovery)
    # ------------------------------------------------------------------

    async def _deep_crawl(self, live_hosts: list[str]) -> dict:
        """Collect HTTP headers and basic endpoint hints."""
        endpoints: list[str] = []
        technologies: list[str] = []
        async with httpx.AsyncClient(
            timeout=self._settings.request_timeout, follow_redirects=True
        ) as client:
            for host in live_hosts:
                for path in ["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
                    try:
                        resp = await client.get(f"https://{host}{path}")
                        if resp.status_code == 200:
                            endpoints.append(f"https://{host}{path}")
                        # Detect tech from headers
                        server = resp.headers.get("server", "")
                        if server and server not in technologies:
                            technologies.append(server)
                        powered_by = resp.headers.get("x-powered-by", "")
                        if powered_by and powered_by not in technologies:
                            technologies.append(powered_by)
                    except Exception:
                        pass
        return {"interesting_endpoints": endpoints, "technologies": technologies}

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    async def run(self) -> dict:
        """Execute the full 4-phase recon pipeline."""
        # Phase 1
        passive = await self._passive_recon()
        subdomains: list[str] = passive["subdomains"]

        # Phase 2
        active = await self._active_recon(subdomains)
        live_hosts: list[str] = active["live_hosts"]

        # Phase 3
        crawl = await self._deep_crawl(live_hosts)

        raw_data = {
            "target": self._target,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            **crawl,
        }

        # Phase 4: LLM synthesis
        try:
            from agents.recon import ReconAgent

            agent = ReconAgent()
            attack_surface = await agent.synthesise(raw_data)
        except Exception:
            attack_surface = raw_data

        return attack_surface
