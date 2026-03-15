from __future__ import annotations

import json
import uuid
from typing import Optional

import httpx
import structlog

from agents.auditor import AuditorAgent
from core.config import settings
from core.scope import Scope
from models.target import AttackSurface, Endpoint
from tools.safe_executor import SafeExecutor
from tools.tool_registry import ToolRegistry

logger = structlog.get_logger()


class ReconAgent:
    """Builds a complete attack surface through 4-phase reconnaissance."""

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

    def build_attack_surface(self, target: str) -> AttackSurface:
        """Run all 4 recon phases and return a synthesized AttackSurface."""
        logger.info("recon_started", session_id=self.session_id, target=target)

        phase1 = self._phase1_passive(target)
        phase2 = self._phase2_active(target, phase1)
        phase3 = self._phase3_deep_crawl(target, phase2)

        # Phase 4 – LLM synthesis
        synthesis = self.auditor.synthesize_attack_surface(
            {"phase1": phase1, "phase2": phase2, "phase3": phase3, "target": target}
        )

        endpoints: list[Endpoint] = []
        for ep_url in synthesis.get("interesting_endpoints", []):
            endpoints.append(
                Endpoint(
                    url=ep_url,
                    method="GET",
                    parameters=[],
                    auth_required=False,
                    tech_hints=[],
                    response_sample="",
                )
            )

        return AttackSurface(
            target=target,
            subdomains=synthesis.get("subdomains", phase1.get("raw_subdomains", [])),
            live_hosts=synthesis.get("live_hosts", phase2.get("live_hosts", [])),
            open_ports=phase2.get("open_ports", {}),
            services=phase2.get("services", {}),
            tech_stack=synthesis.get("tech_stack", {}),
            endpoints=endpoints,
            api_routes=phase3.get("api_routes", []),
            interesting_endpoints=synthesis.get("interesting_endpoints", []),
            attack_vectors=synthesis.get("attack_vectors", []),
        )

    # ------------------------------------------------------------------
    # Phase 1 – Passive recon
    # ------------------------------------------------------------------

    def _phase1_passive(self, target: str) -> dict:
        logger.info("recon_phase1_passive", session_id=self.session_id)
        raw_subdomains: list[str] = []
        historical_endpoints: list[str] = []

        # subfinder
        sf_wrapper = self.registry.get("subfinder")
        if sf_wrapper and sf_wrapper.is_available():
            from models.task import AttackTask

            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title="Subfinder",
                target_endpoint=target,
                vulnerability_hypothesis="subdomain enumeration",
                attack_type="network",
                tool="subfinder",
                tool_flags="-silent -json",
            )
            result = self.executor.run(sf_wrapper.build_command(task), timeout=120)
            for item in sf_wrapper.parse_output(result.stdout, result.stderr):
                raw_subdomains.append(item["subdomain"])

        # crt.sh certificate transparency
        crt_subs = self._fetch_crtsh(target)
        raw_subdomains.extend(crt_subs)

        # Deduplicate
        raw_subdomains = list(set(raw_subdomains))

        return {
            "raw_subdomains": raw_subdomains,
            "historical_endpoints": historical_endpoints,
        }

    def _fetch_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh for certificate transparency subdomains."""
        subdomains: list[str] = []
        try:
            resp = httpx.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lstrip("*.")
                        if line and domain in line:
                            subdomains.append(line)
        except Exception as exc:
            logger.warning("crtsh_failed", error=str(exc))
        return list(set(subdomains))

    # ------------------------------------------------------------------
    # Phase 2 – Active probing
    # ------------------------------------------------------------------

    def _phase2_active(self, target: str, phase1: dict) -> dict:
        logger.info("recon_phase2_active", session_id=self.session_id)
        live_hosts: list[str] = []
        open_ports: dict[str, list[int]] = {}
        services: dict[str, str] = {}
        tech_stack: dict = {}

        all_hosts = [target] + phase1.get("raw_subdomains", [])

        # httpx probe
        hx_wrapper = self.registry.get("httpx")
        if hx_wrapper and hx_wrapper.is_available():
            from models.task import AttackTask

            for host in all_hosts[:50]:  # cap to avoid excessive scans
                task = AttackTask(
                    task_id=str(uuid.uuid4()),
                    title="HTTPx probe",
                    target_endpoint=host if host.startswith("http") else f"http://{host}",
                    vulnerability_hypothesis="http probing",
                    attack_type="network",
                    tool="httpx",
                    tool_flags="",
                )
                result = self.executor.run(hx_wrapper.build_command(task), timeout=60)
                for item in hx_wrapper.parse_output(result.stdout, result.stderr):
                    url = item.get("url", "")
                    if url:
                        live_hosts.append(url)
                    for tech in item.get("technologies", []):
                        tech_stack[tech] = True

        # nmap port scan on primary target
        nmap_wrapper = self.registry.get("nmap")
        if nmap_wrapper and nmap_wrapper.is_available():
            from models.task import AttackTask

            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title="Nmap scan",
                target_endpoint=target,
                vulnerability_hypothesis="port scanning",
                attack_type="network",
                tool="nmap",
                tool_flags="-sV -sC --open",
            )
            result = self.executor.run(nmap_wrapper.build_command(task), timeout=300)
            for item in nmap_wrapper.parse_output(result.stdout, result.stderr):
                ip = item.get("ip", target)
                port = int(item.get("port", 0))
                if port:
                    open_ports.setdefault(ip, []).append(port)
                service = item.get("service", "")
                version = item.get("version", "")
                if service:
                    services[f"{ip}:{port}"] = f"{service} {version}".strip()

        return {
            "live_hosts": list(set(live_hosts)),
            "open_ports": open_ports,
            "services": services,
            "tech_stack": tech_stack,
        }

    # ------------------------------------------------------------------
    # Phase 3 – Deep crawl
    # ------------------------------------------------------------------

    def _phase3_deep_crawl(self, target: str, phase2: dict) -> dict:
        logger.info("recon_phase3_deep_crawl", session_id=self.session_id)
        all_endpoints: list[str] = []
        parameters: dict[str, list[str]] = {}
        api_routes: list[str] = []

        base_url = target if target.startswith("http") else f"http://{target}"

        # katana crawl
        katana_wrapper = self.registry.get("katana")
        if katana_wrapper and katana_wrapper.is_available():
            from models.task import AttackTask

            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title="Katana crawl",
                target_endpoint=base_url,
                vulnerability_hypothesis="deep crawl",
                attack_type="network",
                tool="katana",
                tool_flags="-d 3 -jc -kf all -json",
            )
            result = self.executor.run(katana_wrapper.build_command(task), timeout=300)
            for item in katana_wrapper.parse_output(result.stdout, result.stderr):
                url = item.get("url", "")
                if url:
                    all_endpoints.append(url)
                    if "/api/" in url or url.endswith(".json"):
                        api_routes.append(url)

        # ffuf directory fuzzing
        ffuf_wrapper = self.registry.get("ffuf")
        if ffuf_wrapper and ffuf_wrapper.is_available():
            from models.task import AttackTask

            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title="FFuf directory fuzzing",
                target_endpoint=base_url,
                vulnerability_hypothesis="directory discovery",
                attack_type="network",
                tool="ffuf",
                tool_flags="",
            )
            result = self.executor.run(ffuf_wrapper.build_command(task), timeout=300)
            for item in ffuf_wrapper.parse_output(result.stdout, result.stderr):
                url = item.get("url", "")
                if url:
                    all_endpoints.append(url)

        # arjun parameter discovery on first few endpoints
        arjun_wrapper = self.registry.get("arjun")
        if arjun_wrapper and arjun_wrapper.is_available():
            from models.task import AttackTask

            for ep in all_endpoints[:10]:
                task = AttackTask(
                    task_id=str(uuid.uuid4()),
                    title="Arjun param discovery",
                    target_endpoint=ep,
                    vulnerability_hypothesis="hidden parameters",
                    attack_type="network",
                    tool="arjun",
                    tool_flags="--json",
                )
                result = self.executor.run(arjun_wrapper.build_command(task), timeout=120)
                for item in arjun_wrapper.parse_output(result.stdout, result.stderr):
                    parameters[item.get("url", ep)] = item.get("parameters", [])

        return {
            "all_endpoints": list(set(all_endpoints)),
            "parameters": parameters,
            "api_routes": list(set(api_routes)),
        }
