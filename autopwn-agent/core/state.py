"""LangGraph-compatible state for a pentest session."""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict


class PentestState(TypedDict):
    # Session metadata
    session_id: str
    target: str
    scope: dict

    # Recon output
    attack_surface: dict

    # Planning
    attack_plan: list[dict]
    current_task_index: int

    # Execution accumulators (LangGraph reducer: append)
    findings: Annotated[list, operator.add]
    failed_attempts: Annotated[list, operator.add]
    successful_techniques: Annotated[list, operator.add]

    # Chain analysis
    exploit_graph: dict
    kill_chains: list[dict]

    # Agent reflections
    current_hypothesis: str
    auditor_notes: Annotated[list, operator.add]
    iteration_count: int
    max_iterations: int

    # Control
    status: str
    error: str | None
