from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackTask:
    technique: str
    description: str
    tool: str
    priority: int = 5
    target: str = ""
    parameters: dict = None

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class ScanTask:
    tool: str
    target: str
    options: dict = None

    def __post_init__(self):
        if self.options is None:
            self.options = {}
