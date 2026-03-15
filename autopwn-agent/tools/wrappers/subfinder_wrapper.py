from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class SubfinderWrapper(BaseToolWrapper):
    name = "subfinder"
    binary = "subfinder"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "subfinder",
            "-d",
            task.target_endpoint,
            "-silent",
            "-json",
        ]

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                subdomain = obj.get("host", "")
            except json.JSONDecodeError:
                # Fallback: plain-text subdomain list
                subdomain = line

            if subdomain:
                findings.append(
                    {
                        "type": "subdomain",
                        "subdomain": subdomain,
                        "title": f"Subdomain: {subdomain}",
                        "severity": "info",
                    }
                )
        return findings
