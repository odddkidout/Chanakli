from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class DalfoxWrapper(BaseToolWrapper):
    name = "dalfox"
    binary = "dalfox"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "dalfox",
            "url",
            task.target_endpoint,
            "--format",
            "json",
            "--silence",
        ]

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Dalfox emits objects with "type": "POC" on confirmed XSS
            if obj.get("type") in ("POC", "WEAK", "FOUND"):
                findings.append(
                    {
                        "type": "xss",
                        "title": f"XSS: {obj.get('param', '')} @ {obj.get('evidence', '')}",
                        "severity": "high",
                        "endpoint": obj.get("evidence", ""),
                        "parameter": obj.get("param", ""),
                        "payload": obj.get("poc", ""),
                        "raw": obj,
                    }
                )
        return findings
