from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET

from tools.wrappers import BaseToolWrapper


class NmapWrapper(BaseToolWrapper):
    name = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-sV", "--open", "-oX", "-", target]

    def parse_output(self, output: str) -> dict | list | None:
        try:
            root = ET.fromstring(output)
            hosts = []
            for host in root.findall("host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                ports_data = []
                for port in host.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    if state is not None and state.get("state") == "open":
                        ports_data.append({
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "service": service.get("name", "") if service is not None else "",
                            "version": service.get("version", "") if service is not None else "",
                        })
                if ports_data:
                    hosts.append({"host": addr, "open_ports": ports_data})
            return hosts or None
        except Exception:
            return None
