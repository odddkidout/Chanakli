from __future__ import annotations

from typing import Annotated, Optional
import operator
from typing_extensions import TypedDict


class PentestState(TypedDict):
    # Session
    session_id: str
    target: str
    scope: dict  # allowed IPs, domains, paths, ports

    # Recon
    attack_surface: dict  # subdomains, ports, services, endpoints, tech stack

    # Planning
    attack_plan: list[dict]  # ordered list of AttackTask dicts
    current_task_index: int

    # Execution
    findings: Annotated[list, operator.add]  # accumulated findings
    failed_attempts: Annotated[list, operator.add]  # what didn't work + why
    successful_techniques: Annotated[list, operator.add]

    # Chains
    exploit_graph: dict  # serializable graph representation
    kill_chains: list[dict]

    # Agent state
    current_hypothesis: str
    auditor_notes: Annotated[list, operator.add]
    iteration_count: int
    max_iterations: int

    # Control
    status: str  # "recon" | "planning" | "scanning" | "chaining" | "verifying" | "done"
    error: Optional[str]
