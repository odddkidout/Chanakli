"""LangGraph state machine orchestrating the full pentest pipeline."""
from __future__ import annotations

import asyncio
from typing import Any

from langgraph.graph import END, StateGraph

from core.state import PentestState


# ---------------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------------


async def recon_node(state: PentestState) -> dict:
    """Run the recon engine against the target and populate attack_surface."""
    try:
        from engines.recon_engine import ReconEngine

        engine = ReconEngine(target=state["target"], scope=state["scope"])
        attack_surface = await engine.run()
        return {"attack_surface": attack_surface, "status": "planning"}
    except Exception as exc:
        return {"error": str(exc), "status": "planning", "attack_surface": {}}


async def planning_node(state: PentestState) -> dict:
    """Auditor agent generates an ordered attack plan from the attack surface."""
    try:
        from agents.auditor import AuditorAgent

        agent = AuditorAgent()
        plan = await agent.plan(
            target=state["target"],
            attack_surface=state["attack_surface"],
            failed_attempts=state.get("failed_attempts", []),
        )
        return {
            "attack_plan": plan,
            "current_task_index": 0,
            "status": "scanning",
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
    except Exception as exc:
        return {"error": str(exc), "status": "done"}


async def execution_node(state: PentestState) -> dict:
    """Executor agent runs the current task from the attack plan."""
    try:
        from agents.executor import ExecutorAgent

        plan = state.get("attack_plan", [])
        idx = state.get("current_task_index", 0)

        if idx >= len(plan):
            return {"status": "chaining"}

        task = plan[idx]
        agent = ExecutorAgent(scope=state["scope"])
        result = await agent.execute(task)

        updates: dict[str, Any] = {"current_task_index": idx + 1}
        if result.get("success"):
            updates["findings"] = [result["finding"]]
            updates["successful_techniques"] = [task.get("technique", "unknown")]
        else:
            updates["failed_attempts"] = [
                {"task": task, "reason": result.get("error", "unknown")}
            ]

        next_status = "scanning" if idx + 1 < len(plan) else "chaining"
        updates["status"] = next_status
        return updates
    except Exception as exc:
        return {"error": str(exc), "status": "chaining"}


async def verification_node(state: PentestState) -> dict:
    """Verify findings, eliminate false positives."""
    try:
        from engines.verifier import VerificationEngine

        engine = VerificationEngine(scope=state["scope"])
        verified = await engine.verify_all(state.get("findings", []))
        # Store verified subset separately (plain replacement, not appended)
        return {"verified_findings": verified, "status": "chaining"}
    except Exception as exc:
        return {"error": str(exc), "status": "chaining", "verified_findings": []}


async def chain_analysis_node(state: PentestState) -> dict:
    """Build exploit graph and identify kill chains using verified findings."""
    try:
        from engines.chain_engine import ChainEngine

        engine = ChainEngine()
        # Prefer verified findings for chain analysis; fall back to all findings
        findings_for_chain = state.get("verified_findings") or state.get("findings", [])
        graph, chains = await engine.analyse(findings_for_chain)
        return {"exploit_graph": graph, "kill_chains": chains, "status": "reflecting"}
    except Exception as exc:
        return {"error": str(exc), "status": "reflecting", "exploit_graph": {}, "kill_chains": []}


async def reflection_node(state: PentestState) -> dict:
    """Auditor reflects on results, decides to re-plan or finish."""
    try:
        from agents.auditor import AuditorAgent

        agent = AuditorAgent()
        note, should_continue = await agent.reflect(
            findings=state.get("findings", []),
            failed_attempts=state.get("failed_attempts", []),
            iteration=state.get("iteration_count", 0),
            max_iterations=state.get("max_iterations", 10),
        )
        status = "planning" if should_continue else "done"
        return {"auditor_notes": [note], "status": status}
    except Exception as exc:
        return {"error": str(exc), "status": "done"}


async def done_node(state: PentestState) -> dict:
    """Finalise the session."""
    return {"status": "done"}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _route_after_reflection(state: PentestState) -> str:
    return state.get("status", "done")


def build_graph() -> Any:
    g = StateGraph(PentestState)

    g.add_node("recon", recon_node)
    g.add_node("planning", planning_node)
    g.add_node("execution", execution_node)
    g.add_node("verification", verification_node)
    g.add_node("chain_analysis", chain_analysis_node)
    g.add_node("reflection", reflection_node)
    g.add_node("done", done_node)

    g.set_entry_point("recon")
    g.add_edge("recon", "planning")
    g.add_edge("planning", "execution")
    g.add_edge("execution", "verification")
    g.add_edge("verification", "chain_analysis")
    g.add_edge("chain_analysis", "reflection")
    g.add_conditional_edges(
        "reflection",
        _route_after_reflection,
        {"planning": "planning", "done": "done"},
    )
    g.add_edge("done", END)

    return g.compile()


_compiled_graph = None


def _get_graph() -> Any:
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


async def run_pentest(
    session_id: str,
    target: str,
    scope: dict,
    max_iterations: int = 10,
) -> dict:
    """Run a full pentest session and return the final state."""
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
        "verified_findings": [],
        "exploit_graph": {},
        "kill_chains": [],
        "current_hypothesis": "",
        "auditor_notes": [],
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "status": "recon",
        "error": None,
    }

    graph = _get_graph()
    final_state = await graph.ainvoke(initial_state)
    return dict(final_state)
