from __future__ import annotations

import json
import os
import shutil
import tempfile

from tools.wrappers import BaseToolWrapper


class ArjunWrapper(BaseToolWrapper):
    name = "arjun"

    def is_available(self) -> bool:
        return shutil.which("arjun") is not None

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        fd, out_file = tempfile.mkstemp(prefix="arjun_", suffix=".json")
        os.close(fd)
        return ["-u", target, "--json", "-oJ", out_file]

    def parse_output(self, output: str) -> dict | None:
        try:
            data = json.loads(output)
            params = data.get("params", [])
            if params:
                return {
                    "title": "Hidden parameters discovered",
                    "severity": "medium",
                    "parameters": params,
                    "tool": "arjun",
                }
        except Exception:
            pass
        return None
