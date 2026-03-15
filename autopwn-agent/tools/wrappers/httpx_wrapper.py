from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class HttpxWrapper(BaseToolWrapper):
    name = "httpx"
    binary = "httpx"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "httpx",
            "-u",
            task.target_endpoint,
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-follow-redirects",
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
                    "type": "http_probe",
                    "title": f"HTTP: {obj.get('url', '')} [{obj.get('status-code', '')}]",
                    "severity": "info",
                    "url": obj.get("url", ""),
                    "final_url": obj.get("final-url", ""),
                    "status_code": obj.get("status-code", 0),
                    "title_text": obj.get("title", ""),
                    "technologies": obj.get("tech", []),
                    "content_length": obj.get("content-length", 0),
                    "webserver": obj.get("webserver", ""),
                }
            )
        return findings
