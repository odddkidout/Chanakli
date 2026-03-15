from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackTask:
    task_id: str
    title: str
    target_endpoint: str
    vulnerability_hypothesis: str
    attack_type: str  # sqli|xss|ssrf|lfi|rce|idor|auth_bypass|jwt|xxe|ssti|open_redirect|priv_esc|network
    tool: str  # sqlmap|nuclei|ffuf|manual|nmap|dalfox|arjun|jwt_tool
    tool_flags: str
    requires_auth: bool = False
    auth_token: Optional[str] = None
    depends_on_task_id: Optional[str] = None
    estimated_impact: str = "medium"  # low|medium|high|critical
    chain_potential: str = ""
    priority: int = 1


@dataclass
class ScanTask:
    task_id: str
    scan_type: str  # port_scan|web_scan|vuln_scan
    target: str
    options: dict = field(default_factory=dict)


@dataclass
class TaskResult:
    task_id: str
    success: bool
    raw_output: str
    parsed_findings: list[dict] = field(default_factory=list)
    new_endpoints_discovered: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
