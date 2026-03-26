from __future__ import annotations

import json
import shutil

from tools.wrappers import BaseToolWrapper


class FfufWrapper(BaseToolWrapper):
    name = "ffuf"

    def is_available(self) -> bool:
        return shutil.which("ffuf") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-u", f"{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-of", "json", "-o", "/tmp/ffuf.json"]

    def parse_output(self, output: str) -> list | None:
        try:
            data = json.loads(output)
            results = data.get("results", [])
            return [
                {
                    "title": f"Discovered endpoint: {r.get('url', '')}",
                    "severity": "info",
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "tool": "ffuf",
                }
                for r in results
            ] or None
        except Exception:
            return None
