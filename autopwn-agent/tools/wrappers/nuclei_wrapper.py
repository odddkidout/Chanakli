from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class NucleiWrapper(BaseToolWrapper):
    name = "nuclei"
    binary = "nuclei"

    def build_command(self, task: "AttackTask") -> list[str]:
        # Parse optional tags and severity from tool_flags
        tags = "cve,misconfiguration,exposure"
        severity = "medium,high,critical"
        if task.tool_flags:
            parts = task.tool_flags.split()
            for i, p in enumerate(parts):
                if p == "-tags" and i + 1 < len(parts):
                    tags = parts[i + 1]
                if p == "-severity" and i + 1 < len(parts):
                    severity = parts[i + 1]

        return [
            "nuclei",
            "-u",
            task.target_endpoint,
            "-tags",
            tags,
            "-severity",
            severity,
            "-json",
            "-silent",
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

            findings.append(
                {
                    "type": "nuclei",
                    "title": obj.get("info", {}).get("name", "Unknown"),
                    "severity": obj.get("info", {}).get("severity", "info"),
                    "endpoint": obj.get("matched-at", ""),
                    "template_id": obj.get("template-id", ""),
                    "extracted_results": obj.get("extracted-results", []),
                    "matcher_name": obj.get("matcher-name", ""),
                    "raw": obj,
                }
            )
        return findings
