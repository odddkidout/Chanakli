from __future__ import annotations

import json
import os
import shutil
import tempfile

from tools.wrappers import BaseToolWrapper

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_FALLBACK_WORDLIST = "/usr/share/wordlists/dirb/small.txt"


class FfufWrapper(BaseToolWrapper):
    name = "ffuf"

    def is_available(self) -> bool:
        return shutil.which("ffuf") is not None

    def _wordlist(self) -> str:
        for path in (_DEFAULT_WORDLIST, _FALLBACK_WORDLIST):
            if os.path.isfile(path):
                return path
        return ""

    def build_command(self, task: dict) -> list[str]:
        target = task.get("target", "")
        wordlist = self._wordlist()
        fd, out_file = tempfile.mkstemp(prefix="ffuf_", suffix=".json")
        os.close(fd)
        args = ["-u", f"{target}/FUZZ", "-of", "json", "-o", out_file]
        if wordlist:
            args += ["-w", wordlist]
        return args

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
