from __future__ import annotations

import shutil

from tools.wrappers import BaseToolWrapper


class SubfinderWrapper(BaseToolWrapper):
    name = "subfinder"

    def is_available(self) -> bool:
        return shutil.which("subfinder") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-d", target, "-silent"]

    def parse_output(self, output: str) -> list | None:
        subdomains = [line.strip() for line in output.splitlines() if line.strip()]
        if not subdomains:
            return None
        return [{"title": f"Subdomain: {s}", "severity": "info", "host": s, "tool": "subfinder"} for s in subdomains]
