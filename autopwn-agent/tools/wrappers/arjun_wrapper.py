from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class ArjunWrapper(BaseToolWrapper):
    name = "arjun"
    binary = "arjun"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "arjun",
            "-u",
            task.target_endpoint,
            "--json",
        ]

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        # arjun returns {"<url>": {"params": [...]}, ...}
        for url, info in data.items():
            params = info.get("params", [])
            if params:
                findings.append(
                    {
                        "type": "hidden_parameters",
                        "title": f"Hidden Parameters @ {url}",
                        "severity": "info",
                        "url": url,
                        "parameters": params,
                    }
                )
        return findings
