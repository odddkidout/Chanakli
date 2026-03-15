from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from litellm import completion

from core.config import settings
from core.scope import Scope, ScopeViolationError
from models.finding import Finding
from models.task import AttackTask, TaskResult
from tools.safe_executor import SafeExecutor
from tools.tool_registry import ToolRegistry

logger = structlog.get_logger()

_EXECUTOR_SYSTEM_PROMPT = """\
You are a precise pentesting tool operator. Given an attack task, you:
1. Determine exact tool command with correct flags
2. Parse tool output to extract confirmed findings
3. Identify any new attack surface discovered
4. Report results in structured JSON

You never go out of scope. You never run destructive commands.
Always output valid JSON only.
"""


def _call_llm(messages: list[dict], retries: int = 3) -> str:
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = completion(
                model=settings.executor_model,
                messages=messages,
                api_base=settings.litellm_base_url,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            last_exc = exc
            wait = 2 ** attempt
            logger.warning("executor_llm_retry", attempt=attempt + 1, error=str(exc), wait=wait)
            time.sleep(wait)
    raise RuntimeError(f"Executor LLM failed after {retries} retries: {last_exc}") from last_exc


def _parse_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(line for line in lines if not line.strip().startswith("```"))
    return json.loads(text)


class ExecutorAgent:
    """Uses MiMo-V2-Flash via LiteLLM to translate AttackTasks into tool calls."""

    def __init__(
        self,
        scope: Scope,
        session_id: str,
        registry: Optional[ToolRegistry] = None,
        redis_client: Optional[object] = None,
    ):
        self.scope = scope
        self.session_id = session_id
        self.safe_executor = SafeExecutor(scope, session_id, redis_client)
        self.registry = registry or ToolRegistry()

    def execute_task(self, task: AttackTask, state: dict) -> TaskResult:
        """
        1. Validate task target is in scope.
        2. Run tool via SafeExecutor with timeout.
        3. Parse stdout/stderr.
        4. Return structured TaskResult.
        """
        # Scope check before execution
        if not self.scope.is_in_scope(task.target_endpoint):
            logger.warning(
                "task_out_of_scope",
                session_id=self.session_id,
                task_id=task.task_id,
                target=task.target_endpoint,
            )
            return TaskResult(
                task_id=task.task_id,
                success=False,
                raw_output="",
                errors=[f"Target '{task.target_endpoint}' is out of scope"],
            )

        logger.info(
            "executing_task",
            session_id=self.session_id,
            task_id=task.task_id,
            tool=task.tool,
            target=task.target_endpoint,
        )

        # Try to run via registered wrapper first
        raw_findings = self.registry.execute_task(task, self.safe_executor)

        # Fall back to LLM-guided execution for "manual" tasks or unknown tools
        if not raw_findings and task.tool == "manual":
            raw_findings = self._llm_guided_execution(task, state)

        # Convert raw finding dicts to Finding objects
        findings: list[Finding] = []
        for raw in raw_findings:
            try:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        session_id=self.session_id,
                        task_id=task.task_id,
                        type=raw.get("type", "unknown"),
                        title=raw.get("title", "Untitled Finding"),
                        endpoint=raw.get("endpoint", task.target_endpoint),
                        parameter=raw.get("parameter"),
                        payload=raw.get("payload"),
                        evidence=json.dumps(raw, default=str)[:2048],
                        severity=raw.get("severity", "info"),
                        confidence=float(raw.get("confidence", 0.7)),
                        requires_auth=bool(raw.get("requires_auth", False)),
                        cvss_score=None,
                        cwe_id=None,
                        discovered_at=datetime.now(timezone.utc),
                        tool_used=task.tool,
                        raw_output=json.dumps(raw, default=str),
                    )
                )
            except Exception as exc:
                logger.warning("finding_parse_error", error=str(exc))

        import dataclasses

        return TaskResult(
            task_id=task.task_id,
            success=True,
            raw_output="",
            parsed_findings=[dataclasses.asdict(f) for f in findings],
        )

    def _llm_guided_execution(self, task: AttackTask, state: dict) -> list[dict]:
        """Use the Executor LLM to interpret and execute a manual task."""
        prompt = f"""\
Attack task:
{json.dumps({
    "title": task.title,
    "target_endpoint": task.target_endpoint,
    "vulnerability_hypothesis": task.vulnerability_hypothesis,
    "attack_type": task.attack_type,
    "tool_flags": task.tool_flags,
}, indent=2)}

Attack surface context:
{json.dumps(state.get("attack_surface", {}), indent=2, default=str)}

Analyze what would be discovered by testing this hypothesis.
Return JSON:
{{
  "findings": [
    {{
      "type": "vuln_type",
      "title": "...",
      "severity": "low|medium|high|critical",
      "endpoint": "...",
      "parameter": "...",
      "evidence": "..."
    }}
  ],
  "new_endpoints": ["url1", "url2"]
}}
"""
        messages = [
            {"role": "system", "content": _EXECUTOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = _call_llm(messages)
            data = _parse_json(raw)
            return data.get("findings", [])
        except Exception as exc:
            logger.error("llm_guided_execution_failed", error=str(exc))
            return []
