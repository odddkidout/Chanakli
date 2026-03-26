from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status_code: int = 0
    technologies: list[str] = field(default_factory=list)


@dataclass
class AttackSurface:
    target: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)


@dataclass
class Target:
    host: str
    url: str
    scope: dict
    attack_surface: AttackSurface = field(default_factory=lambda: AttackSurface(target=""))
