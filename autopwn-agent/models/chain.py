from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChainEdge:
    source: str
    target: str
    chainable: bool = True
    description: str = ""


@dataclass
class ExploitChain:
    nodes: list[str] = field(default_factory=list)
    edges: list[ChainEdge] = field(default_factory=list)


@dataclass
class KillChain:
    path: list[str]
    steps: list[str]
    score: float = 0.0
    length: int = 0
