"""SafeExecutor — sandboxed async subprocess runner with scope enforcement."""
from __future__ import annotations

import asyncio
from typing import Any

from core.scope import Scope, ScopeViolationError


class SafeExecutor:
    def __init__(self, scope: Scope, timeout: int = 120) -> None:
        self._scope = scope
        self._timeout = timeout

    async def run(self, command: list[str]) -> dict:
        """Run *command* in a subprocess and return stdout/stderr/returncode."""
        self._scope.validate_command(command)  # raises ScopeViolationError if out of scope

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {self._timeout}s",
                    "command": command,
                }
            return {
                "returncode": proc.returncode,
                "stdout": stdout_b.decode("utf-8", errors="replace"),
                "stderr": stderr_b.decode("utf-8", errors="replace"),
                "command": command,
            }
        except FileNotFoundError:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Binary not found: {command[0]}",
                "command": command,
            }
