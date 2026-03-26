"""Scope enforcement — validates targets before any command is executed."""
from __future__ import annotations

import ipaddress
import re


class ScopeViolationError(Exception):
    """Raised when a command targets a host outside the allowed scope."""


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


class Scope:
    """Holds scope configuration and provides validation helpers."""

    def __init__(self, scope: dict) -> None:
        self._domains: list[str] = scope.get("domains", [])
        self._cidrs: list[ipaddress.IPv4Network] = [
            ipaddress.ip_network(c, strict=False) for c in scope.get("cidrs", [])
        ]
        self._allowed_ports: set[int] = set(scope.get("ports", [80, 443]))

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def is_domain_allowed(self, domain: str) -> bool:
        domain = domain.lower()
        for pattern in self._domains:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                suffix = pattern[1:]  # keeps the leading dot
                if domain.endswith(suffix) or domain == suffix[1:]:
                    return True
            elif domain == pattern:
                return True
        return False

    def is_ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._cidrs)

    def validate_command(self, tokens: list[str]) -> None:
        """Raise ScopeViolationError if any token resolves to an out-of-scope host."""
        text = " ".join(tokens)
        for ip in _IP_RE.findall(text):
            if not self.is_ip_allowed(ip):
                raise ScopeViolationError(f"IP {ip!r} is outside the allowed CIDR scope")
        for domain in _DOMAIN_RE.findall(text):
            if not self.is_domain_allowed(domain):
                raise ScopeViolationError(f"Domain {domain!r} is outside the allowed scope")
