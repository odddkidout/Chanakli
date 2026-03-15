from __future__ import annotations

import dataclasses
import uuid
from typing import Any, Callable, Optional

import structlog
from langgraph.graph import END, StateGraph

from agents.auditor import AuditorAgent
from agents.executor import ExecutorAgent
from core.config import settings
from core.scope import Scope
from core.state import PentestState
from engines.chain_engine import ChainEngine
from engines.recon_engine import ReconEngine
from engines.verifier import VerificationEngine
from models.finding import Finding, VerifiedFinding
from models.task import AttackTask

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------------


def _make_recon_node(
    scope: Scope, session_id: str, redis_client: Optional[Any] = None
) -> Callable[[PentestState], dict]:
    engine = ReconEngine(scope, session_id, redis_client=redis_client)

    def recon_node(state: PentestState) -> dict:
        logger.info("node_start", node="recon", session_id=state["session_id"])
        try:
            surface = engine.run(state["target"])
            return {"attack_surface": surface, "status": "planning"}
        except Exception as exc:
            logger.error("recon_node_error", error=str(exc))
            return {"error": str(exc), "status": "planning", "attack_surface": {}}

    return recon_node


def _make_planning_node(auditor: AuditorAgent) -> Callable[[PentestState], dict]:
    def planning_node(state: PentestState) -> dict:
        logger.info("node_start", node="planning", session_id=state["session_id"])
        try:
            tasks = auditor.generate_attack_plan(
                state["attack_surface"], state.get("failed_attempts", [])
            )
            plan_dicts = [dataclasses.asdict(t) for t in tasks]
            return {
                "attack_plan": plan_dicts,
                "current_task_index": 0,
                "status": "scanning",
                "error": None,
            }
        except Exception as exc:
            logger.error("planning_node_error", error=str(exc))
            return {"error": str(exc), "status": "scanning"}

    return planning_node


def _make_execution_node(
    executor: ExecutorAgent,
) -> Callable[[PentestState], dict]:
    def execution_node(state: PentestState) -> dict:
        logger.info("node_start", node="execution", session_id=state["session_id"])
        plan = state.get("attack_plan", [])
        idx = state.get("current_task_index", 0)

        if idx >= len(plan):
            return {"status": "verifying"}

        task_dict = plan[idx]
        try:
            task = AttackTask(**task_dict)
            result = executor.execute_task(task, dict(state))

            new_findings = result.parsed_findings
            failed: list[dict] = []
            if not result.success or (not new_findings and result.errors):
                failed = [
                    {
                        "task_id": task.task_id,
                        "title": task.title,
                        "errors": result.errors,
                        "reason": "no findings returned",
                    }
                ]

            return {
                "findings": new_findings,
                "failed_attempts": failed,
                "current_task_index": idx + 1,
                "status": "verifying",
                "error": None,
            }
        except Exception as exc:
            logger.error("execution_node_error", error=str(exc))
            return {
                "failed_attempts": [{"task_id": task_dict.get("task_id"), "error": str(exc)}],
                "current_task_index": idx + 1,
                "status": "verifying",
                "error": str(exc),
            }

    return execution_node


def _make_verification_node(
    verifier: VerificationEngine,
) -> Callable[[PentestState], dict]:
    def verification_node(state: PentestState) -> dict:
        logger.info("node_start", node="verification", session_id=state["session_id"])
        raw_findings = state.get("findings", [])
        verified_findings: list[dict] = []

        # Dedup set
        seen_keys: set[str] = set()

        for raw in raw_findings:
            try:
                # raw is already a dict from executor
                finding = Finding(
                    finding_id=raw.get("finding_id", str(uuid.uuid4())),
                    session_id=state["session_id"],
                    task_id=raw.get("task_id", ""),
                    type=raw.get("type", "unknown"),
                    title=raw.get("title", ""),
                    endpoint=raw.get("endpoint", ""),
                    parameter=raw.get("parameter"),
                    payload=raw.get("payload"),
                    evidence=raw.get("evidence", ""),
                    severity=raw.get("severity", "info"),
                    confidence=float(raw.get("confidence", 0.5)),
                    requires_auth=bool(raw.get("requires_auth", False)),
                    cvss_score=raw.get("cvss_score"),
                    cwe_id=raw.get("cwe_id"),
                    discovered_at=raw.get("discovered_at"),
                    tool_used=raw.get("tool_used", ""),
                    raw_output=raw.get("raw_output", ""),
                )

                dedup_key = finding.dedup_key()
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                vf = verifier.verify_finding(finding, finding.raw_output)
                if vf.verified:
                    verified_findings.append(dataclasses.asdict(vf))
            except Exception as exc:
                logger.warning("verification_error", error=str(exc))

        return {
            "findings": verified_findings,
            "status": "chaining",
            "error": None,
        }

    return verification_node


def _make_chain_analysis_node(
    chain_engine: ChainEngine,
) -> Callable[[PentestState], dict]:
    def chain_analysis_node(state: PentestState) -> dict:
        logger.info("node_start", node="chain_analysis", session_id=state["session_id"])
        raw_findings = state.get("findings", [])

        try:
            findings = [_dict_to_finding(f) for f in raw_findings if isinstance(f, dict)]
            findings_map = {f.finding_id: f for f in findings}

            G = chain_engine.build_exploit_graph(findings)
            kill_chains = chain_engine.find_kill_chains(G, findings_map)

            return {
                "exploit_graph": chain_engine.to_serializable(G),
                "kill_chains": [dataclasses.asdict(kc) for kc in kill_chains],
                "status": "verifying",  # will move to reflection next
                "error": None,
            }
        except Exception as exc:
            logger.error("chain_analysis_error", error=str(exc))
            return {"error": str(exc), "exploit_graph": {}, "kill_chains": []}

    return chain_analysis_node


def _make_reflection_node(
    auditor: AuditorAgent,
) -> Callable[[PentestState], dict]:
    def reflection_node(state: PentestState) -> dict:
        logger.info("node_start", node="reflection", session_id=state["session_id"])
        try:
            reflection = auditor.reflect_on_failures(
                state.get("failed_attempts", []),
                state.get("attack_surface", {}),
            )
            notes = [
                f"Iteration {state.get('iteration_count', 0)}: "
                + ", ".join(reflection.new_hypotheses[:3])
            ]
            new_hypothesis = (
                reflection.new_hypotheses[0] if reflection.new_hypotheses else ""
            )
            return {
                "auditor_notes": notes,
                "current_hypothesis": new_hypothesis,
                "iteration_count": state.get("iteration_count", 0) + 1,
                "status": "planning" if reflection.pivot_approach else "scanning",
                "error": None,
            }
        except Exception as exc:
            logger.error("reflection_node_error", error=str(exc))
            return {
                "iteration_count": state.get("iteration_count", 0) + 1,
                "error": str(exc),
            }

    return reflection_node


def _make_done_node() -> Callable[[PentestState], dict]:
    def done_node(state: PentestState) -> dict:
        logger.info(
            "node_start",
            node="done",
            session_id=state["session_id"],
            findings_count=len(state.get("findings", [])),
        )
        return {"status": "done"}

    return done_node


# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------


def _reflection_router(state: PentestState) -> str:
    """Route from reflection node."""
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", settings.max_iterations)
    plan = state.get("attack_plan", [])
    idx = state.get("current_task_index", 0)

    if iteration >= max_iter:
        return "done"
    if idx >= len(plan):
        return "done"
    if state.get("status") == "planning":
        return "planning"
    return "execution"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph(
    scope: Scope,
    session_id: str,
    redis_client: Optional[Any] = None,
) -> Any:
    """Build and compile the LangGraph state machine."""
    auditor = AuditorAgent()
    from agents.executor import ExecutorAgent
    executor_agent = ExecutorAgent(scope, session_id, redis_client=redis_client)
    verifier = VerificationEngine(scope, session_id, auditor=auditor, redis_client=redis_client)
    chain_engine = ChainEngine(auditor=auditor)

    workflow = StateGraph(PentestState)

    # Add nodes
    workflow.add_node("recon", _make_recon_node(scope, session_id, redis_client))
    workflow.add_node("planning", _make_planning_node(auditor))
    workflow.add_node("execution", _make_execution_node(executor_agent))
    workflow.add_node("verification", _make_verification_node(verifier))
    workflow.add_node("chain_analysis", _make_chain_analysis_node(chain_engine))
    workflow.add_node("reflection", _make_reflection_node(auditor))
    workflow.add_node("done", _make_done_node())

    # Set entry point
    workflow.set_entry_point("recon")

    # Static edges
    workflow.add_edge("recon", "planning")
    workflow.add_edge("planning", "execution")
    workflow.add_edge("execution", "verification")
    workflow.add_edge("verification", "chain_analysis")
    workflow.add_edge("chain_analysis", "reflection")
    workflow.add_edge("done", END)

    # Conditional edge from reflection
    workflow.add_conditional_edges(
        "reflection",
        _reflection_router,
        {
            "planning": "planning",
            "execution": "execution",
            "done": "done",
        },
    )

    return workflow.compile()


def run_pentest(
    target: str,
    scope: dict,
    session_id: Optional[str] = None,
    max_iterations: int = 50,
    redis_client: Optional[Any] = None,
) -> PentestState:
    """Run a complete automated pentest and return final state."""
    session_id = session_id or str(uuid.uuid4())
    scope_obj = Scope(scope)
    graph = build_graph(scope_obj, session_id, redis_client)

    initial_state: PentestState = {
        "session_id": session_id,
        "target": target,
        "scope": scope,
        "attack_surface": {},
        "attack_plan": [],
        "current_task_index": 0,
        "findings": [],
        "failed_attempts": [],
        "successful_techniques": [],
        "exploit_graph": {},
        "kill_chains": [],
        "current_hypothesis": "",
        "auditor_notes": [],
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "status": "recon",
        "error": None,
    }

    final_state = graph.invoke(initial_state)
    return final_state


def _dict_to_finding(d: dict) -> Finding:
    from datetime import datetime, timezone

    return Finding(
        finding_id=d.get("finding_id", str(uuid.uuid4())),
        session_id=d.get("session_id", ""),
        task_id=d.get("task_id", ""),
        type=d.get("type", "unknown"),
        title=d.get("title", ""),
        endpoint=d.get("endpoint", ""),
        parameter=d.get("parameter"),
        payload=d.get("payload"),
        evidence=d.get("evidence", ""),
        severity=d.get("severity", "info"),
        confidence=float(d.get("confidence", 0.5)),
        requires_auth=bool(d.get("requires_auth", False)),
        cvss_score=d.get("cvss_score"),
        cwe_id=d.get("cwe_id"),
        discovered_at=d.get("discovered_at") or datetime.now(timezone.utc),
        tool_used=d.get("tool_used", ""),
        raw_output=d.get("raw_output", ""),
    )
