from __future__ import annotations

import json
import shutil

from tools.wrappers import BaseToolWrapper


class HttpxWrapper(BaseToolWrapper):
    name = "httpx"

    def is_available(self) -> bool:
        return shutil.which("httpx") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-u", target, "-json", "-silent", "-tech-detect", "-status-code"]

    def parse_output(self, output: str) -> list | None:
        findings = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                findings.append({
                    "title": f"Live host: {data.get('url', '')}",
                    "severity": "info",
                    "url": data.get("url", ""),
                    "status": data.get("status-code", 0),
                    "technologies": data.get("tech", []),
                    "tool": "httpx",
                })
            except Exception:
                pass
        return findings or None
