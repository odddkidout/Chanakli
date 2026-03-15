from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

import structlog

from core.scope import Scope, ScopeViolationError

logger = structlog.get_logger()


@dataclass
class ExecutionResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    scope_error: Optional[str] = None


class SafeExecutor:
    """Runs tool sub-processes in a sandboxed, scope-validated manner."""

    def __init__(self, scope: Scope, session_id: str, redis_client: Optional[object] = None):
        self.scope = scope
        self.session_id = session_id
        self._redis = redis_client
        self.execution_log: list[dict] = []

    def _log_command(self, command: list[str]) -> None:
        entry = {"ts": time.time(), "cmd": command, "session_id": self.session_id}
        self.execution_log.append(entry)
        if self._redis is not None:
            import json

            key = f"session:{self.session_id}:exec_log"
            self._redis.rpush(key, json.dumps(entry))
            self._redis.expire(key, 86400)
        logger.info(
            "command_executed",
            session_id=self.session_id,
            command=" ".join(command),
        )

    def validate_scope(self, command: list[str]) -> None:
        """Raise ScopeViolationError if any target in command is out of scope."""
        self.scope.validate_command(command)

    def run(self, command: list[str], timeout: int = 60) -> ExecutionResult:
        """
        1. Validate every IP/domain in command is in scope.
        2. Log command to execution_log + Redis.
        3. Run in subprocess with timeout.
        4. Capture stdout, stderr, return code.
        5. Return ExecutionResult.
        """
        # Scope check – mandatory before every execution
        try:
            self.validate_scope(command)
        except ScopeViolationError as exc:
            logger.warning(
                "scope_violation",
                session_id=self.session_id,
                command=" ".join(command),
                error=str(exc),
            )
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr="",
                scope_error=str(exc),
            )

        self._log_command(command)

        timed_out = False
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ExecutionResult(
                command=command,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.warning(
                "command_timeout",
                session_id=self.session_id,
                command=" ".join(command),
                timeout=timeout,
            )
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                timed_out=True,
            )
        except FileNotFoundError as exc:
            logger.error(
                "binary_not_found",
                session_id=self.session_id,
                command=command[0],
                error=str(exc),
            )
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"Binary not found: {command[0]}",
            )
        except Exception as exc:
            logger.error(
                "command_error",
                session_id=self.session_id,
                command=" ".join(command),
                error=str(exc),
            )
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=str(exc),
            )
