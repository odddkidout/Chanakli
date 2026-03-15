from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class NmapWrapper(BaseToolWrapper):
    name = "nmap"
    binary = "nmap"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "nmap",
            "-sV",
            "-sC",
            "--open",
            "-oX",
            "-",  # XML output to stdout
            task.target_endpoint,
        ]

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        if not stdout.strip():
            return findings

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return findings

        for host in root.findall("host"):
            addr_elem = host.find("address")
            ip = addr_elem.get("addr", "") if addr_elem is not None else ""

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                portid = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                state_elem = port.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""
                if state != "open":
                    continue

                service_elem = port.find("service")
                service_name = ""
                service_version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    service_version = f"{product} {version}".strip()

                # Collect NSE script results
                scripts: dict[str, str] = {}
                for script in port.findall("script"):
                    scripts[script.get("id", "")] = script.get("output", "")

                # Check for CVE mentions in script output
                cve_mentions = [
                    s for s in scripts.values() if "CVE-" in s
                ]

                finding: dict = {
                    "type": "open_port",
                    "ip": ip,
                    "port": portid,
                    "protocol": protocol,
                    "service": service_name,
                    "version": service_version,
                    "scripts": scripts,
                    "cve_mentions": cve_mentions,
                    "title": f"Open port {portid}/{protocol} ({service_name})",
                    "severity": "info",
                }
                findings.append(finding)

        return findings
