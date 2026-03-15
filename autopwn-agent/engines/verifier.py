from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Optional

import structlog

from agents.auditor import AuditorAgent
from core.config import settings
from core.scope import Scope
from models.finding import Finding, VerifiedFinding
from tools.safe_executor import SafeExecutor
from tools.tool_registry import ToolRegistry

logger = structlog.get_logger()

CONFIDENCE_THRESHOLD = settings.verification_confidence_threshold
REPRODUCIBILITY_RUNS = settings.verification_reproducibility_runs
REQUIRED_SUCCESSES = settings.verification_required_successes

# Known WAF fingerprints in response headers/bodies
_WAF_FINGERPRINTS = [
    "cloudflare",
    "sucuri",
    "akamai",
    "imperva",
    "f5 big-ip",
    "barracuda",
    "fortigate",
    "__utm",
]


class VerificationEngine:
    """Verifies findings and eliminates false positives."""

    def __init__(
        self,
        scope: Scope,
        session_id: str,
        auditor: Optional[AuditorAgent] = None,
        redis_client: Optional[object] = None,
    ):
        self.scope = scope
        self.session_id = session_id
        self.auditor = auditor or AuditorAgent()
        self.executor = SafeExecutor(scope, session_id, redis_client)
        self.registry = ToolRegistry()

    def verify_finding(self, finding: Finding, tool_output: str) -> VerifiedFinding:
        """
        Verification pipeline:
        1. Re-run the exact exploit 3 times → must be reproducible (≥2/3).
        2. Auditor LLM checks: is the response evidence conclusive?
        3. WAF/honeypot detection.
        4. Confidence score computation.
        """
        false_positive_indicators: list[str] = []
        exploitation_steps: list[str] = []
        chain_opportunities: list[str] = []
        remediation = ""

        # Step 1: Reproducibility check
        successes = self._reproducibility_check(finding)
        reproducible = successes >= REQUIRED_SUCCESSES
        if not reproducible:
            false_positive_indicators.append(
                f"Only {successes}/{REPRODUCIBILITY_RUNS} reproduction runs succeeded."
            )

        # Step 2: WAF detection
        waf_detected = self._detect_waf(tool_output)
        if waf_detected:
            false_positive_indicators.append("WAF/honeypot fingerprint detected in response.")

        # Step 3: LLM verification
        llm_confirmed = self.auditor.verify_finding(finding, tool_output)
        if not llm_confirmed:
            false_positive_indicators.append("LLM assessed evidence as inconclusive.")

        # Step 4: Confidence score
        confidence = self._compute_confidence(
            reproducible=reproducible,
            waf_detected=waf_detected,
            llm_confirmed=llm_confirmed,
            successes=successes,
        )

        # Enrich with exploitation steps and remediation if confident
        if confidence >= CONFIDENCE_THRESHOLD:
            try:
                enriched = self.auditor.analyze_finding(finding, {"tool_output": tool_output[:2048]})
                exploitation_steps = enriched.exploitation_steps
                chain_opportunities = enriched.chain_opportunities
                remediation = enriched.remediation
                if enriched.cvss_score:
                    finding.cvss_score = enriched.cvss_score
            except Exception as exc:
                logger.warning("enrichment_failed", error=str(exc))

        verified = confidence >= CONFIDENCE_THRESHOLD and not false_positive_indicators

        logger.info(
            "finding_verified",
            session_id=self.session_id,
            finding_id=finding.finding_id,
            verified=verified,
            confidence=confidence,
        )

        return VerifiedFinding(
            **asdict(finding),
            verified=verified,
            verification_runs=REPRODUCIBILITY_RUNS,
            false_positive_indicators=false_positive_indicators,
            exploitation_steps=exploitation_steps,
            chain_opportunities=chain_opportunities,
            remediation=remediation,
        )

    def _reproducibility_check(self, finding: Finding) -> int:
        """Re-run the finding's tool/endpoint up to REPRODUCIBILITY_RUNS times."""
        successes = 0
        wrapper = self.registry.get(finding.tool_used)
        if wrapper is None or not wrapper.is_available():
            # Can't re-run without wrapper; assume 1 success (the original)
            return 1

        from models.task import AttackTask

        for _ in range(REPRODUCIBILITY_RUNS):
            task = AttackTask(
                task_id=str(uuid.uuid4()),
                title=f"Verify: {finding.title}",
                target_endpoint=finding.endpoint,
                vulnerability_hypothesis=finding.title,
                attack_type=finding.type,
                tool=finding.tool_used,
                tool_flags="",
            )
            cmd = wrapper.build_command(task)
            result = self.executor.run(cmd, timeout=60)
            parsed = wrapper.parse_output(result.stdout, result.stderr)
            if parsed:
                successes += 1

        return successes

    def _detect_waf(self, response_text: str) -> bool:
        lower = response_text.lower()
        return any(fp in lower for fp in _WAF_FINGERPRINTS)

    def _compute_confidence(
        self,
        reproducible: bool,
        waf_detected: bool,
        llm_confirmed: bool,
        successes: int,
    ) -> float:
        score = 0.0
        # Reproducibility: up to 0.4
        score += (successes / REPRODUCIBILITY_RUNS) * 0.4
        # LLM confirmation: 0.4
        if llm_confirmed:
            score += 0.4
        # WAF penalty: -0.2
        if waf_detected:
            score -= 0.2
        return max(0.0, min(1.0, round(score, 2)))
