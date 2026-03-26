from __future__ import annotations

import re
import shutil

from tools.wrappers import BaseToolWrapper


class JwtToolWrapper(BaseToolWrapper):
    name = "jwt_tool"

    def is_available(self) -> bool:
        return shutil.which("jwt_tool") is not None

    def build_command(self, task: dict) -> list[str]:
        token = task.get("token", "")
        return [token, "-M", "at"]

    def parse_output(self, output: str) -> dict | None:
        if "VULNERABLE" in output or "alg:none" in output.lower():
            return {
                "title": "JWT Vulnerability",
                "severity": "critical",
                "details": output[:2000],
                "tool": "jwt_tool",
            }
        return None
