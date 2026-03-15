from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class SqlmapWrapper(BaseToolWrapper):
    name = "sqlmap"
    binary = "sqlmap"

    def build_command(self, task: "AttackTask") -> list[str]:
        session_id = "default"
        output_dir = f"/tmp/sqlmap/{session_id}"
        cmd = [
            "sqlmap",
            "-u",
            task.target_endpoint,
            "--batch",
            "--level=3",
            "--risk=2",
            f"--output-dir={output_dir}",
        ]
        if task.tool_flags:
            cmd.extend(task.tool_flags.split())
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        combined = stdout + stderr

        # Detect injectable parameters
        injectable_params: list[str] = []
        for match in re.finditer(
            r"Parameter: (\S+) .+? is vulnerable", combined
        ):
            injectable_params.append(match.group(1))

        # Detect DB type
        db_type = ""
        db_match = re.search(r"back-end DBMS: (.+)", combined)
        if db_match:
            db_type = db_match.group(1).strip()

        if injectable_params:
            findings.append(
                {
                    "type": "sqli",
                    "title": "SQL Injection",
                    "severity": "critical",
                    "injectable_parameters": injectable_params,
                    "db_type": db_type,
                    "raw_output": combined[:4096],
                }
            )

        return findings
