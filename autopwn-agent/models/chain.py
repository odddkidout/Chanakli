from __future__ import annotations

from dataclasses import dataclass, field

from models.finding import Finding


@dataclass
class ChainEdge:
    source_finding_id: str
    target_finding_id: str
    method: str  # how A enables B
    combined_impact: str  # low | medium | high | critical


@dataclass
class ExploitChain:
    chain_id: str
    findings: list[Finding]
    edges: list[ChainEdge]
    total_impact: str
    score: float


@dataclass
class KillChain:
    chain_id: str
    steps: list[Finding]
    total_impact: str
    score: float
    narrative: str  # LLM-generated plain-English attack story
    prerequisites: list[str] = field(default_factory=list)
