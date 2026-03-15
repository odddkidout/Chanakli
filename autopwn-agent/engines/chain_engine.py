from __future__ import annotations

import json
import uuid
from typing import Optional

import networkx as nx
import structlog

from agents.auditor import AuditorAgent
from models.chain import ChainEdge, ExploitChain, KillChain
from models.finding import Finding

logger = structlog.get_logger()


class ChainEngine:
    """Builds exploit dependency graphs and discovers kill chains."""

    def __init__(self, auditor: Optional[AuditorAgent] = None):
        self.auditor = auditor or AuditorAgent()

    def build_exploit_graph(self, findings: list[Finding]) -> nx.DiGraph:
        """
        Each finding is a node. Edges represent "A enables B" relationships.
        The Auditor LLM evaluates chainability between each pair.
        """
        G: nx.DiGraph = nx.DiGraph()

        for f in findings:
            G.add_node(
                f.finding_id,
                finding_id=f.finding_id,
                type=f.type,
                endpoint=f.endpoint,
                severity=f.severity,
                requires_auth=f.requires_auth,
                title=f.title,
                confidence=f.confidence,
            )

        # Evaluate chainability for each ordered pair (A, B)
        for i, f1 in enumerate(findings):
            for j, f2 in enumerate(findings):
                if i == j:
                    continue
                chain_info = self._evaluate_chainability(f1, f2)
                if chain_info.get("chainable"):
                    G.add_edge(
                        f1.finding_id,
                        f2.finding_id,
                        method=chain_info.get("method", ""),
                        combined_impact=chain_info.get("combined_impact", "low"),
                    )

        logger.info(
            "exploit_graph_built",
            nodes=G.number_of_nodes(),
            edges=G.number_of_edges(),
        )
        return G

    def _evaluate_chainability(self, f1: Finding, f2: Finding) -> dict:
        prompt = f"""\
Finding A: {json.dumps({"type": f1.type, "endpoint": f1.endpoint, "severity": f1.severity, "title": f1.title}, default=str)}
Finding B: {json.dumps({"type": f2.type, "endpoint": f2.endpoint, "severity": f2.severity, "title": f2.title}, default=str)}

Can exploiting A enable, amplify, or unlock exploitation of B?
Consider: credential reuse, session escalation, SSRF to internal services,
file write to RCE, info disclosure enabling auth bypass, etc.

Return JSON: {{"chainable": bool, "method": "how", "combined_impact": "low|medium|high|critical"}}
"""
        try:
            import time
            from litellm import completion
            from core.config import settings

            for attempt in range(3):
                try:
                    resp = completion(
                        model=settings.auditor_model,
                        messages=[{"role": "user", "content": prompt}],
                        api_base=settings.litellm_base_url,
                    )
                    text = resp.choices[0].message.content or "{}"
                    text = text.strip()
                    if text.startswith("```"):
                        lines = text.splitlines()
                        text = "\n".join(
                            line for line in lines if not line.strip().startswith("```")
                        )
                    return json.loads(text)
                except Exception as exc:
                    wait = 2 ** attempt
                    logger.warning("chain_llm_retry", attempt=attempt + 1, error=str(exc))
                    time.sleep(wait)
        except Exception as exc:
            logger.error("chainability_eval_failed", error=str(exc))
        return {"chainable": False, "method": "", "combined_impact": "low"}

    def find_kill_chains(self, G: nx.DiGraph, findings_map: dict[str, Finding]) -> list[KillChain]:
        """
        Find all paths from unauthenticated entry nodes to critical-impact nodes.
        Score each chain by: impact × exploitability × chain_length_penalty.
        """
        # Entry nodes: findings that don't require auth
        entry_nodes = [
            n for n, d in G.nodes(data=True) if not d.get("requires_auth", False)
        ]
        # Critical nodes: high/critical severity findings
        critical_nodes = [
            n for n, d in G.nodes(data=True)
            if d.get("severity", "low") in ("high", "critical")
        ]

        impact_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        kill_chains: list[KillChain] = []
        seen_paths: set[tuple] = set()

        for entry in entry_nodes:
            for target in critical_nodes:
                if entry == target:
                    continue
                try:
                    paths = list(nx.all_simple_paths(G, entry, target, cutoff=6))
                except nx.NetworkXError:
                    continue

                for path in paths:
                    path_key = tuple(path)
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)

                    steps = [findings_map[node_id] for node_id in path if node_id in findings_map]
                    if not steps:
                        continue

                    max_severity = max(
                        (impact_scores.get(f.severity, 1) for f in steps),
                        default=1,
                    )
                    total_confidence = sum(f.confidence for f in steps) / len(steps)
                    length_penalty = 1.0 / len(steps)
                    score = max_severity * total_confidence * (1 - length_penalty * 0.1)

                    severity_str = ["low", "low", "medium", "high", "critical"][
                        min(max(max_severity, 1), 4)
                    ]

                    # Generate narrative
                    try:
                        narrative = self.auditor.generate_chain_narrative(
                            [{"type": f.type, "title": f.title, "endpoint": f.endpoint} for f in steps]
                        )
                    except Exception:
                        narrative = f"Chain of {len(steps)} exploits leading to {severity_str} impact."

                    kill_chains.append(
                        KillChain(
                            chain_id=str(uuid.uuid4()),
                            steps=steps,
                            total_impact=severity_str,
                            score=round(score, 3),
                            narrative=narrative,
                            prerequisites=[
                                f.title for f in steps if f.requires_auth
                            ],
                        )
                    )

        kill_chains.sort(key=lambda c: c.score, reverse=True)
        logger.info("kill_chains_found", count=len(kill_chains))
        return kill_chains

    def to_serializable(self, G: nx.DiGraph) -> dict:
        """Convert a DiGraph to a JSON-serializable dict."""
        return {
            "nodes": [
                {"id": n, **d} for n, d in G.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **d} for u, v, d in G.edges(data=True)
            ],
        }
