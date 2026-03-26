"""Chain engine — exploit dependency graph + kill chain discovery."""
from __future__ import annotations

import json
from typing import Any

import networkx as nx

from core.config import Settings


class ChainEngine:
    def __init__(self) -> None:
        self._settings = Settings()

    async def analyse(self, findings: list[dict]) -> tuple[dict, list[dict]]:
        """Build an exploit graph and find kill chains."""
        G = nx.DiGraph()

        for i, finding in enumerate(findings):
            node_id = f"f{i}"
            G.add_node(
                node_id,
                title=finding.get("title", f"finding-{i}"),
                severity=finding.get("severity", "info"),
                confidence=finding.get("confidence", 0.5),
            )

        # Simple heuristic: chain info → low → medium → high → critical
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        nodes_by_severity: dict[str, list[str]] = {}
        for node_id, data in G.nodes(data=True):
            sev = data.get("severity", "info")
            nodes_by_severity.setdefault(sev, []).append(node_id)

        sev_keys = sorted(severity_order.keys(), key=lambda s: severity_order[s])
        for i, sev in enumerate(sev_keys[:-1]):
            next_sev = sev_keys[i + 1]
            for src in nodes_by_severity.get(sev, []):
                for dst in nodes_by_severity.get(next_sev, []):
                    G.add_edge(src, dst, chainable=True)

        # Serialise graph
        graph_data = {
            "nodes": [
                {"id": n, **d} for n, d in G.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **d} for u, v, d in G.edges(data=True)
            ],
        }

        # Find kill chains (longest paths) — limit pairs evaluated for performance
        kill_chains: list[dict] = []
        sources = [n for n in G.nodes() if G.in_degree(n) == 0]
        sinks = [n for n in G.nodes() if G.out_degree(n) == 0]
        for source in sources[:20]:
            for target in sinks[:20]:
                if source == target:
                    continue
                try:
                    paths = list(nx.all_simple_paths(G, source, target, cutoff=6))
                    for path in paths[:50]:
                        chain_severity = max(
                            (severity_order.get(G.nodes[n].get("severity", "info"), 0) for n in path),
                            default=0,
                        )
                        kill_chains.append(
                            {
                                "path": path,
                                "length": len(path),
                                "score": chain_severity * len(path),
                                "steps": [G.nodes[n].get("title", n) for n in path],
                            }
                        )
                except Exception:
                    pass

        kill_chains.sort(key=lambda c: c["score"], reverse=True)
        return graph_data, kill_chains[:10]
