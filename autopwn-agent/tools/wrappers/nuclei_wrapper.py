from __future__ import annotations

import json
import shutil

from tools.wrappers import BaseToolWrapper


class NucleiWrapper(BaseToolWrapper):
    name = "nuclei"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-u", target, "-json", "-silent"]

    def parse_output(self, output: str) -> list | None:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "title": data.get("info", {}).get("name", "nuclei-finding"),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "url": data.get("matched-at", ""),
                    "host": data.get("host", ""),
                    "template": data.get("template-id", ""),
                    "tool": "nuclei",
                })
            except json.JSONDecodeError:
                pass
        return findings or None
