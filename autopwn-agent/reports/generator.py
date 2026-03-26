"""Report generator — structured Markdown and JSON exports."""
from __future__ import annotations

import json
from datetime import datetime, timezone


class ReportGenerator:
    def generate(
        self,
        session_id: str,
        target: str,
        findings: list[dict],
        kill_chains: list[dict],
        attack_surface: dict,
        fmt: str = "markdown",
    ) -> str:
        if fmt == "json":
            return self._json(session_id, target, findings, kill_chains, attack_surface)
        return self._markdown(session_id, target, findings, kill_chains, attack_surface)

    def _markdown(
        self,
        session_id: str,
        target: str,
        findings: list[dict],
        kill_chains: list[dict],
        attack_surface: dict,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        lines = [
            f"# AutoPwn Agent — Pentest Report",
            f"",
            f"**Target:** {target}  ",
            f"**Session:** {session_id}  ",
            f"**Generated:** {now}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"- **Total findings:** {len(findings)}",
            f"- **Verified findings:** {sum(1 for f in findings if f.get('verified'))}",
            f"- **Kill chains identified:** {len(kill_chains)}",
            f"",
        ]

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if severity_counts:
            lines += ["## Severity Breakdown", ""]
            for sev, count in sorted(severity_counts.items()):
                lines.append(f"- **{sev.capitalize()}:** {count}")
            lines.append("")

        # Attack surface
        if attack_surface:
            lines += ["## Attack Surface", ""]
            if attack_surface.get("subdomains"):
                lines.append(f"**Subdomains ({len(attack_surface['subdomains'])}):**")
                for s in attack_surface["subdomains"][:20]:
                    lines.append(f"- {s}")
                lines.append("")
            if attack_surface.get("technologies"):
                lines.append(f"**Technologies:** {', '.join(attack_surface['technologies'])}")
                lines.append("")

        # Findings
        if findings:
            lines += ["## Findings", ""]
            for i, f in enumerate(findings, 1):
                lines += [
                    f"### {i}. {f.get('title', 'Unknown')}",
                    f"",
                    f"- **Severity:** {f.get('severity', 'info')}",
                    f"- **URL:** {f.get('url', f.get('host', 'N/A'))}",
                    f"- **Tool:** {f.get('tool', 'N/A')}",
                    f"- **Verified:** {f.get('verified', False)}",
                ]
                if f.get("remediation"):
                    lines.append(f"- **Remediation:** {f['remediation']}")
                lines.append("")

        # Kill chains
        if kill_chains:
            lines += ["## Kill Chains", ""]
            for i, chain in enumerate(kill_chains, 1):
                lines += [
                    f"### Chain {i} (score: {chain.get('score', 0):.1f})",
                    f"",
                    f"**Path:** " + " → ".join(chain.get("steps", [])),
                    f"",
                ]

        return "\n".join(lines)

    def _json(
        self,
        session_id: str,
        target: str,
        findings: list[dict],
        kill_chains: list[dict],
        attack_surface: dict,
    ) -> str:
        return json.dumps(
            {
                "session_id": session_id,
                "target": target,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "findings": findings,
                "kill_chains": kill_chains,
                "attack_surface": attack_surface,
            },
            default=str,
            indent=2,
        )
