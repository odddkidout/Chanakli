from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import structlog

from agents.auditor import AuditorAgent

logger = structlog.get_logger()


class ReportGenerator:
    """Generates structured pentest reports in Markdown and JSON formats."""

    def __init__(self, auditor: Optional[AuditorAgent] = None):
        self.auditor = auditor or AuditorAgent()

    def generate(self, session_data: dict, fmt: str = "markdown") -> str:
        """
        Generate a complete pentest report.
        fmt: "markdown" | "json"
        """
        if fmt == "json":
            return self._generate_json(session_data)
        return self._generate_markdown(session_data)

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _generate_markdown(self, data: dict) -> str:
        sections: list[str] = []

        # 1. Executive Summary
        exec_summary = self._safe_exec_summary(data)
        sections.append(f"# Penetration Test Report\n\n## Executive Summary\n\n{exec_summary}")

        # 2. Attack Surface Overview
        surface = data.get("attack_surface", {})
        sections.append(self._attack_surface_section(surface))

        # 3. Findings Table
        findings = data.get("findings", [])
        sections.append(self._findings_table(findings))

        # 4. Kill Chains
        kill_chains = data.get("kill_chains", [])
        sections.append(self._kill_chains_section(kill_chains))

        # 5. Individual Finding Details
        sections.append(self._finding_details(findings))

        # 6. Failed Attempts Log
        failed = data.get("failed_attempts", [])
        sections.append(self._failed_attempts_section(failed))

        # 7. Recommendations
        sections.append(self._recommendations_section(findings))

        return "\n\n---\n\n".join(sections)

    def _safe_exec_summary(self, data: dict) -> str:
        try:
            return self.auditor.generate_executive_summary(
                {
                    "target": data.get("target"),
                    "findings_count": len(data.get("findings", [])),
                    "kill_chains_count": len(data.get("kill_chains", [])),
                    "severities": self._severity_counts(data.get("findings", [])),
                }
            )
        except Exception:
            findings = data.get("findings", [])
            counts = self._severity_counts(findings)
            return (
                f"This penetration test against **{data.get('target', 'unknown')}** "
                f"identified {len(findings)} verified findings. "
                f"Severity breakdown: Critical={counts.get('critical', 0)}, "
                f"High={counts.get('high', 0)}, Medium={counts.get('medium', 0)}, "
                f"Low={counts.get('low', 0)}."
            )

    @staticmethod
    def _severity_counts(findings: list[dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _attack_surface_section(surface: dict) -> str:
        lines = ["## Attack Surface Overview", ""]
        lines.append(f"- **Subdomains discovered**: {len(surface.get('subdomains', []))}")
        lines.append(f"- **Live hosts**: {len(surface.get('live_hosts', []))}")
        lines.append(f"- **Endpoints mapped**: {len(surface.get('endpoints', []))}")
        lines.append(f"- **API routes**: {len(surface.get('api_routes', []))}")

        tech = surface.get("tech_stack", {})
        if tech:
            lines.append("\n### Technology Stack")
            for k, v in tech.items():
                lines.append(f"- **{k}**: {v}")

        vectors = surface.get("attack_vectors", [])
        if vectors:
            lines.append("\n### Identified Attack Vectors")
            for v in vectors[:10]:
                lines.append(f"- {v}")

        return "\n".join(lines)

    @staticmethod
    def _findings_table(findings: list[dict]) -> str:
        lines = ["## Findings Summary", ""]
        lines.append("| # | Title | Type | Severity | Endpoint | Confidence |")
        lines.append("|---|-------|------|----------|----------|------------|")

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5)
        )

        for i, f in enumerate(sorted_findings, 1):
            title = f.get("title", "")[:60]
            ftype = f.get("type", "")
            sev = f.get("severity", "info")
            endpoint = f.get("endpoint", "")[:50]
            conf = f"{float(f.get('confidence', 0)) * 100:.0f}%"
            lines.append(f"| {i} | {title} | {ftype} | {sev} | {endpoint} | {conf} |")

        return "\n".join(lines)

    @staticmethod
    def _kill_chains_section(kill_chains: list[dict]) -> str:
        if not kill_chains:
            return "## Kill Chains\n\nNo exploit chains identified."

        lines = ["## Kill Chains", ""]
        for i, kc in enumerate(kill_chains[:10], 1):
            lines.append(f"### Chain {i}: {kc.get('total_impact', 'unknown').upper()} impact")
            lines.append(f"**Score**: {kc.get('score', 0):.3f}")
            lines.append(f"**Steps**: {len(kc.get('steps', []))}")
            narrative = kc.get("narrative", "")
            if narrative:
                lines.append(f"\n{narrative}")
            steps = kc.get("steps", [])
            if steps:
                lines.append("\n**Attack Steps:**")
                for j, step in enumerate(steps, 1):
                    title = step.get("title", step.get("type", "Unknown"))
                    lines.append(f"{j}. {title}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _finding_details(findings: list[dict]) -> str:
        if not findings:
            return "## Finding Details\n\nNo findings to report."

        lines = ["## Finding Details", ""]
        for f in findings:
            lines.append(f"### {f.get('title', 'Unknown Finding')}")
            lines.append(f"- **Type**: {f.get('type', '')}")
            lines.append(f"- **Severity**: {f.get('severity', '')}")
            lines.append(f"- **Endpoint**: `{f.get('endpoint', '')}`")
            if f.get("parameter"):
                lines.append(f"- **Parameter**: `{f['parameter']}`")
            if f.get("payload"):
                lines.append(f"- **Payload**: `{f['payload']}`")
            if f.get("cvss_score"):
                lines.append(f"- **CVSS Score**: {f['cvss_score']}")
            if f.get("cwe_id"):
                lines.append(f"- **CWE**: {f['cwe_id']}")
            lines.append(f"- **Confidence**: {float(f.get('confidence', 0)) * 100:.0f}%")

            evidence = f.get("evidence", "")
            if evidence:
                lines.append("\n**Evidence:**")
                lines.append(f"```\n{evidence[:1024]}\n```")

            exp_steps = f.get("exploitation_steps", [])
            if exp_steps:
                lines.append("\n**Exploitation Steps:**")
                for j, step in enumerate(exp_steps, 1):
                    lines.append(f"{j}. {step}")

            remediation = f.get("remediation", "")
            if remediation:
                lines.append(f"\n**Remediation:** {remediation}")

            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _failed_attempts_section(failed: list[dict]) -> str:
        if not failed:
            return "## Failed Attempts Log\n\nNo failed attempts recorded."

        lines = ["## Failed Attempts Log", ""]
        for fa in failed[:50]:
            task_id = fa.get("task_id", "")
            title = fa.get("title", fa.get("task_id", "Unknown"))
            reason = fa.get("reason", fa.get("error", ""))
            lines.append(f"- **{title}** ({task_id[:8]}): {reason}")

        return "\n".join(lines)

    @staticmethod
    def _recommendations_section(findings: list[dict]) -> str:
        lines = ["## Recommendations", ""]
        seen_types: set[str] = set()
        recommendations = {
            "sqli": "Implement parameterised queries / prepared statements for all database interactions.",
            "xss": "Apply context-aware output encoding and a strict Content Security Policy (CSP).",
            "ssrf": "Restrict outbound connections from the application server and validate user-supplied URLs against an allowlist.",
            "rce": "Avoid passing user input to shell commands; use safe API calls instead.",
            "idor": "Enforce server-side authorisation checks on every object access.",
            "auth_bypass": "Review authentication logic; enforce multi-factor authentication on sensitive endpoints.",
            "jwt": "Use strong, randomly generated JWT secrets and validate all header claims server-side.",
            "lfi": "Sanitize file path inputs and use a whitelist of allowed files.",
            "xxe": "Disable external entity processing in XML parsers.",
            "ssti": "Use sandboxed template engines and avoid passing raw user input to templates.",
            "open_redirect": "Validate redirect destinations against a whitelist of allowed URLs.",
        }
        for f in findings:
            ftype = f.get("type", "")
            if ftype not in seen_types and ftype in recommendations:
                seen_types.add(ftype)
                lines.append(f"- **{ftype.upper()}**: {recommendations[ftype]}")

        if not seen_types:
            lines.append("- Remediate all identified findings according to OWASP guidelines.")
            lines.append("- Implement a regular penetration testing cycle.")
            lines.append("- Ensure security patches are applied promptly.")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------

    def _generate_json(self, data: dict) -> str:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": data.get("target"),
            "session_id": data.get("session_id"),
            "summary": {
                "total_findings": len(data.get("findings", [])),
                "severity_counts": self._severity_counts(data.get("findings", [])),
                "kill_chains": len(data.get("kill_chains", [])),
            },
            "attack_surface": data.get("attack_surface", {}),
            "findings": data.get("findings", []),
            "kill_chains": data.get("kill_chains", []),
            "failed_attempts": data.get("failed_attempts", []),
        }
        return json.dumps(report, indent=2, default=str)
