from __future__ import annotations

import shutil

from tools.wrappers import BaseToolWrapper


class KatanaWrapper(BaseToolWrapper):
    name = "katana"

    def is_available(self) -> bool:
        return shutil.which("katana") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        return ["-u", target, "-silent", "-depth", "3"]

    def parse_output(self, output: str) -> list | None:
        urls = [line.strip() for line in output.splitlines() if line.strip().startswith("http")]
        if not urls:
            return None
        return [{"title": f"Crawled URL: {u}", "severity": "info", "url": u, "tool": "katana"} for u in urls]
