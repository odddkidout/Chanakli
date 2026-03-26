from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    title: str
    severity: str
    url: str = ""
    host: str = ""
    tool: str = ""
    details: str = ""
    confidence: float = 0.5
    verified: bool = False
    cve: Optional[str] = None
    remediation: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class VerifiedFinding(Finding):
    reproduction_count: int = 0
    waf_detected: bool = False
