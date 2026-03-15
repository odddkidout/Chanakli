from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Endpoint:
    url: str
    method: str
    parameters: list[str]
    auth_required: bool
    tech_hints: list[str]
    response_sample: str


@dataclass
class AttackSurface:
    target: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)
    tech_stack: dict = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    interesting_endpoints: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)


@dataclass
class Target:
    host: str
    ports: list[int] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
