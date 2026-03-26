"""Session memory: Redis (live state), ChromaDB (technique recall), PostgreSQL (persistence)."""
from __future__ import annotations

import json
import time
from typing import Any


class AttackMemory:
    """Thin wrapper around Redis for per-session state storage."""

    def __init__(self, redis_client: Any, session_id: str, ttl: int = 86400) -> None:
        self._redis = redis_client
        self._session_id = session_id
        self._ttl = ttl

    def _key(self, field: str) -> str:
        return f"autopwn:{self._session_id}:{field}"

    def set(self, field: str, value: Any) -> None:
        serialised = json.dumps(value, default=str)
        self._redis.set(self._key(field), serialised, ex=self._ttl)

    def get(self, field: str, default: Any = None) -> Any:
        raw = self._redis.get(self._key(field))
        if raw is None:
            return default
        return json.loads(raw)

    def append(self, field: str, item: Any) -> None:
        current: list = self.get(field, [])
        current.append(item)
        self.set(field, current)

    def log_command(self, command: list[str], stdout: str, stderr: str, returncode: int) -> None:
        entry = {
            "ts": time.time(),
            "command": command,
            "stdout": stdout[:4096],
            "stderr": stderr[:1024],
            "returncode": returncode,
        }
        self.append("audit_log", entry)
