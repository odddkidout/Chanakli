from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    finding_id: str
    session_id: str
    task_id: str
    type: str  # sqli, xss, ssrf, rce, idor, etc.
    title: str
    endpoint: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: str  # raw response snippet
    severity: str  # low | medium | high | critical
    confidence: float  # 0.0–1.0
    requires_auth: bool
    cvss_score: Optional[float]
    cwe_id: Optional[str]
    discovered_at: datetime
    tool_used: str
    raw_output: str

    def dedup_key(self) -> str:
        """Return a hash key for deduplication based on endpoint + type + parameter."""
        import hashlib

        raw = f"{self.endpoint}::{self.type}::{self.parameter or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class VerifiedFinding(Finding):
    verified: bool = False
    verification_runs: int = 0
    false_positive_indicators: list[str] = field(default_factory=list)
    exploitation_steps: list[str] = field(default_factory=list)
    chain_opportunities: list[str] = field(default_factory=list)
    remediation: str = ""
