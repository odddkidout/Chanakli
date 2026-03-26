"""Executor agent — translates attack tasks into tool calls and parses results."""
from __future__ import annotations

import json
import re
import asyncio
from typing import Any

import httpx

from core.config import Settings
from core.scope import Scope, ScopeViolationError


def _strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


class ExecutorAgent:
    """Calls the Executor LLM to translate tasks → tool invocations, runs them."""

    def __init__(self, scope: dict) -> None:
        self._settings = Settings()
        self._scope = Scope(scope)

    async def _call_llm(self, system: str, user: str, retries: int = 3) -> str:
        payload = {
            "model": self._settings.executor_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }
        delay = 1.0
        last_exc: Exception | None = None
        async with httpx.AsyncClient(base_url=self._settings.litellm_base_url, timeout=60) as client:
            for attempt in range(retries):
                try:
                    resp = await client.post("/chat/completions", json=payload)
                    resp.raise_for_status()
                    return resp.json()["choices"][0]["message"]["content"]
                except Exception as exc:
                    last_exc = exc
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30.0)
        raise RuntimeError(f"LLM call failed after {retries} attempts: {last_exc}")

    async def execute(self, task: dict) -> dict:
        """Execute an attack task. Returns {success, finding|error}."""
        from tools.tool_registry import ToolRegistry

        registry = ToolRegistry()
        tool_name = task.get("tool", "nuclei")
        wrapper = registry.get(tool_name)

        if wrapper is None:
            return {"success": False, "error": f"Tool {tool_name!r} not available"}

        if not wrapper.is_available():
            return {"success": False, "error": f"Tool binary for {tool_name!r} not found"}

        # Ask executor LLM to build the command arguments
        system = (
            "You are a penetration testing tool operator. Given a task and tool, "
            "return a JSON object with key 'args' (list of strings) — the CLI arguments "
            "to pass to the tool (excluding the tool binary name itself)."
        )
        user = f"Task: {json.dumps(task)}\nTool: {tool_name}"

        try:
            raw = await self._call_llm(system, user)
            data = json.loads(_strip_fences(raw))
            args: list[str] = data.get("args", [])
        except Exception:
            args = wrapper.build_command(task)

        command = [tool_name] + args

        try:
            self._scope.validate_command(command)
        except ScopeViolationError as exc:
            return {"success": False, "error": str(exc)}

        from tools.safe_executor import SafeExecutor

        safe = SafeExecutor(scope=self._scope)
        result = await safe.run(command)

        if result["returncode"] != 0:
            return {
                "success": False,
                "error": result["stderr"] or f"Tool exited with code {result['returncode']}",
            }

        finding = wrapper.parse_output(result["stdout"])
        if not finding:
            return {"success": False, "error": "No findings parsed from tool output"}

        return {"success": True, "finding": finding}
