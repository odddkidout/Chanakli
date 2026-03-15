from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class FfufWrapper(BaseToolWrapper):
    name = "ffuf"
    binary = "ffuf"

    def build_command(self, task: "AttackTask") -> list[str]:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if task.tool_flags:
            for part in task.tool_flags.split():
                if part.startswith("-w"):
                    wordlist = part[2:] if len(part) > 2 else wordlist

        target = task.target_endpoint
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        return [
            "ffuf",
            "-u",
            target,
            "-w",
            wordlist,
            "-json",
            "-ac",
            "-mc",
            "200,301,302,403",
        ]

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            findings.append(
                {
                    "type": "directory_found",
                    "title": f"Directory/File: {result.get('url', '')}",
                    "severity": "info",
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                }
            )
        return findings
