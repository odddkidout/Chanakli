from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class KatanaWrapper(BaseToolWrapper):
    name = "katana"
    binary = "katana"

    def build_command(self, task: "AttackTask") -> list[str]:
        return [
            "katana",
            "-u",
            task.target_endpoint,
            "-d",
            "3",
            "-jc",         # JS crawling
            "-kf",
            "all",         # known files
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
                url = obj.get("endpoint", obj.get("url", ""))
            except json.JSONDecodeError:
                url = line

            if url:
                findings.append(
                    {
                        "type": "crawled_url",
                        "title": f"Crawled: {url}",
                        "severity": "info",
                        "url": url,
                        "source": obj.get("source", "") if isinstance(obj, dict) else "",
                    }
                )
        return findings
