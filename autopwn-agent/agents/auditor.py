from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog
from litellm import completion

from core.config import settings
from models.finding import Finding, VerifiedFinding
from models.task import AttackTask

logger = structlog.get_logger()

_AUDITOR_SYSTEM_PROMPT = """\
You are an elite offensive security researcher with 15 years experience.
You think like a real pentester — not a scanner. You reason about business logic,
authentication flows, trust boundaries, and chaining opportunities.

Given an attack surface, generate a prioritized attack plan. Think step by step:
1. What is the most likely vulnerability given the tech stack?
2. What would a real attacker do first to maximize impact with minimum noise?
3. Which findings could chain into critical impact?

Always output valid JSON only. No markdown, no explanation outside JSON.
"""

_PLAN_USER_TEMPLATE = """\
Attack Surface:
{attack_surface_json}

Previously failed attempts (do NOT repeat these):
{failed_attempts_json}

Generate attack plan as JSON array:
[
  {{
    "task_id": "uuid",
    "title": "human readable title",
    "target_endpoint": "url or IP:port",
    "vulnerability_hypothesis": "what you think exists and why",
    "attack_type": "sqli|xss|ssrf|lfi|rce|idor|auth_bypass|jwt|xxe|ssti|open_redirect|priv_esc|network",
    "tool": "sqlmap|nuclei|ffuf|manual|nmap|dalfox|arjun|jwt_tool",
    "tool_flags": "exact flags to pass",
    "requires_auth": false,
    "auth_token": null,
    "depends_on_task_id": null,
    "estimated_impact": "low|medium|high|critical",
    "chain_potential": "what this unlocks if successful",
    "priority": 1
  }}
]
"""


@dataclass
class EnrichedFinding:
    finding: Finding
    is_true_positive: bool
    cvss_score: float
    exploitation_steps: list[str]
    chain_opportunities: list[str]
    remediation: str


@dataclass
class ReflectionResult:
    new_hypotheses: list[str]
    techniques_to_abandon: list[str]
    updated_surface_observations: list[str]
    pivot_approach: bool


def _call_llm(messages: list[dict], retries: int = 3) -> str:
    """Call the Auditor LLM with retry and exponential backoff."""
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = completion(
                model=settings.auditor_model,
                messages=messages,
                api_base=settings.litellm_base_url,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            last_exc = exc
            wait = 2 ** attempt
            logger.warning(
                "llm_retry",
                attempt=attempt + 1,
                error=str(exc),
                wait=wait,
            )
            time.sleep(wait)
    raise RuntimeError(f"LLM call failed after {retries} retries: {last_exc}") from last_exc


def _parse_json(text: str) -> Any:
    """Robustly parse JSON from LLM output, stripping markdown fences if needed."""
    text = text.strip()
    # Strip ```json ... ``` fences
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines if not line.strip().startswith("```")
        )
    return json.loads(text)


class AuditorAgent:
    """Uses GLM-5 via LiteLLM to plan, analyze, reflect, and verify."""

    # ------------------------------------------------------------------
    # Core public methods
    # ------------------------------------------------------------------

    def generate_attack_plan(
        self, attack_surface: dict, failed_attempts: list[dict]
    ) -> list[AttackTask]:
        prompt = _PLAN_USER_TEMPLATE.format(
            attack_surface_json=json.dumps(attack_surface, indent=2),
            failed_attempts_json=json.dumps(failed_attempts, indent=2),
        )
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw = _call_llm(messages)
        try:
            tasks_raw = _parse_json(raw)
        except (json.JSONDecodeError, ValueError):
            logger.error("attack_plan_parse_failed", raw=raw[:500])
            return []

        tasks: list[AttackTask] = []
        for t in tasks_raw:
            try:
                tasks.append(
                    AttackTask(
                        task_id=t.get("task_id", ""),
                        title=t.get("title", ""),
                        target_endpoint=t.get("target_endpoint", ""),
                        vulnerability_hypothesis=t.get("vulnerability_hypothesis", ""),
                        attack_type=t.get("attack_type", ""),
                        tool=t.get("tool", ""),
                        tool_flags=t.get("tool_flags", ""),
                        requires_auth=bool(t.get("requires_auth", False)),
                        auth_token=t.get("auth_token"),
                        depends_on_task_id=t.get("depends_on_task_id"),
                        estimated_impact=t.get("estimated_impact", "medium"),
                        chain_potential=t.get("chain_potential", ""),
                        priority=int(t.get("priority", 1)),
                    )
                )
            except Exception as exc:
                logger.warning("task_parse_error", error=str(exc), raw_task=t)
        return tasks

    def analyze_finding(
        self, finding: Finding, context: dict
    ) -> EnrichedFinding:
        prompt = f"""\
Raw finding:
{json.dumps(_finding_to_dict(finding), indent=2, default=str)}

Context:
{json.dumps(context, indent=2, default=str)}

Return JSON:
{{
  "is_true_positive": true|false,
  "cvss_score": 0.0–10.0,
  "exploitation_steps": ["step1", ...],
  "chain_opportunities": ["what this unlocks", ...],
  "remediation": "how to fix"
}}
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw = _call_llm(messages)
        try:
            data = _parse_json(raw)
        except (json.JSONDecodeError, ValueError):
            data = {}

        return EnrichedFinding(
            finding=finding,
            is_true_positive=bool(data.get("is_true_positive", True)),
            cvss_score=float(data.get("cvss_score", 5.0)),
            exploitation_steps=data.get("exploitation_steps", []),
            chain_opportunities=data.get("chain_opportunities", []),
            remediation=data.get("remediation", ""),
        )

    def reflect_on_failures(
        self, failed_attempts: list[dict], current_surface: dict
    ) -> ReflectionResult:
        prompt = f"""\
Failed attempts so far:
{json.dumps(failed_attempts, indent=2, default=str)}

Current attack surface:
{json.dumps(current_surface, indent=2, default=str)}

Return JSON:
{{
  "new_hypotheses": ["hypothesis 1", ...],
  "techniques_to_abandon": ["technique 1", ...],
  "updated_surface_observations": ["observation 1", ...],
  "pivot_approach": true|false
}}
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw = _call_llm(messages)
        try:
            data = _parse_json(raw)
        except (json.JSONDecodeError, ValueError):
            data = {}

        return ReflectionResult(
            new_hypotheses=data.get("new_hypotheses", []),
            techniques_to_abandon=data.get("techniques_to_abandon", []),
            updated_surface_observations=data.get("updated_surface_observations", []),
            pivot_approach=bool(data.get("pivot_approach", False)),
        )

    def verify_finding(self, finding: Finding, response_evidence: str) -> bool:
        prompt = f"""\
Finding:
{json.dumps(_finding_to_dict(finding), indent=2, default=str)}

Response evidence:
{response_evidence[:4096]}

Is this finding conclusively real (not a false positive)?
Return JSON: {{"confirmed": true|false, "reasoning": "..."}}
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw = _call_llm(messages)
        try:
            data = _parse_json(raw)
            return bool(data.get("confirmed", False))
        except (json.JSONDecodeError, ValueError):
            return False

    def synthesize_attack_surface(self, recon_data: dict) -> dict:
        """Phase 4 synthesis: given all recon phases, produce structured attack surface."""
        prompt = f"""\
Given the following raw recon data, synthesize a structured attack surface.

Recon data:
{json.dumps(recon_data, indent=2, default=str)}

Return JSON:
{{
  "subdomains": [...],
  "live_hosts": [...],
  "tech_stack": {{"framework": "...", "language": "...", "server": "...", "cms": "..."}},
  "interesting_endpoints": [...],
  "authentication_flows": [...],
  "api_schema": {{}},
  "attack_vectors": [...],
  "priority_targets": [...]
}}
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw = _call_llm(messages)
        try:
            return _parse_json(raw)
        except (json.JSONDecodeError, ValueError):
            logger.error("surface_synthesis_failed", raw=raw[:500])
            return {}

    def generate_chain_narrative(self, kill_chain: list[dict]) -> str:
        """Generate a plain-English narrative for a kill chain."""
        prompt = f"""\
Given this kill chain (ordered list of exploits):
{json.dumps(kill_chain, indent=2, default=str)}

Write a concise, plain-English attack story (3-5 sentences) describing how an attacker
would execute this chain from initial access to final impact.

Return plain text only.
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return _call_llm(messages)

    def generate_executive_summary(self, report_data: dict) -> str:
        """Generate a non-technical executive summary for a pentest report."""
        prompt = f"""\
Given this penetration test data:
{json.dumps(report_data, indent=2, default=str)}

Write a concise executive summary (2-3 paragraphs) suitable for a non-technical audience.
Focus on business risk, key findings, and recommendations.

Return plain text only.
"""
        messages = [
            {"role": "system", "content": _AUDITOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return _call_llm(messages)


def _finding_to_dict(finding: Finding) -> dict:
    import dataclasses

    return dataclasses.asdict(finding)
