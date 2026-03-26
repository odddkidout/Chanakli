from __future__ import annotations

import json
import shutil

from tools.wrappers import BaseToolWrapper


class DalfoxWrapper(BaseToolWrapper):
    name = "dalfox"

    def is_available(self) -> bool:
        return shutil.which("dalfox") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["url", target, "--format", "json"]

    def parse_output(self, output: str) -> list | None:
        findings = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                if data.get("type") == "POC":
                    findings.append({
                        "title": "Cross-Site Scripting (XSS)",
                        "severity": "high",
                        "url": data.get("data", ""),
                        "payload": data.get("param", ""),
                        "tool": "dalfox",
                    })
            except Exception:
                pass
        return findings or None
