from __future__ import annotations

import re
import shutil

from tools.wrappers import BaseToolWrapper


class SqlmapWrapper(BaseToolWrapper):
    name = "sqlmap"

    def is_available(self) -> bool:
        return shutil.which("sqlmap") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-u", target, "--batch", "--output-dir=/tmp/sqlmap"]

    def parse_output(self, output: str) -> dict | None:
        if "injectable" in output.lower() or "sql injection" in output.lower():
            urls = re.findall(r"https?://[^\s]+", output)
            return {
                "title": "SQL Injection",
                "severity": "critical",
                "url": urls[0] if urls else "",
                "tool": "sqlmap",
                "details": output[:2000],
            }
        return None
