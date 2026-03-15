from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse


class ScopeViolationError(Exception):
    """Raised when a command targets an out-of-scope host or IP."""


class Scope:
    """Validates that targets are within the defined scope."""

    def __init__(self, scope: dict):
        """
        scope dict may contain:
          - allowed_domains: list[str]
          - allowed_ips: list[str]   (single IPs or CIDR ranges)
          - allowed_ports: list[int]
          - allowed_paths: list[str]  (URL path prefixes)
        """
        self.allowed_domains: list[str] = scope.get("allowed_domains", [])
        self.allowed_ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowed_ports: list[int] = scope.get("allowed_ports", [])
        self.allowed_paths: list[str] = scope.get("allowed_paths", [])

        for ip_entry in scope.get("allowed_ips", []):
            try:
                self.allowed_ip_networks.append(
                    ipaddress.ip_network(ip_entry, strict=False)
                )
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Domain / IP helpers
    # ------------------------------------------------------------------

    def _is_domain_allowed(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        for allowed in self.allowed_domains:
            allowed = allowed.lower().rstrip(".")
            if domain == allowed or domain.endswith("." + allowed):
                return True
        return False

    def _is_ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.allowed_ip_networks:
            if addr in net:
                return True
        return False

    def is_in_scope(self, target: str) -> bool:
        """Return True if *target* (URL, domain, or IP) is in scope."""
        # Try to parse as URL first
        parsed = urlparse(target)
        host = parsed.hostname or target

        # Strip port from bare host:port notation
        if host and ":" in host:
            host = host.split(":")[0]

        if not host:
            return False

        # Try IP check
        try:
            ipaddress.ip_address(host)
            return self._is_ip_allowed(host)
        except ValueError:
            pass

        return self._is_domain_allowed(host)

    # ------------------------------------------------------------------
    # Command-level validation
    # ------------------------------------------------------------------

    # Patterns to extract host/IP tokens from command arguments
    _IP_RE = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
    )
    _DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )

    def _extract_targets_from_command(self, command: list[str]) -> list[str]:
        targets: list[str] = []
        for token in command:
            # Skip flags
            if token.startswith("-"):
                continue
            for match in self._IP_RE.finditer(token):
                targets.append(match.group())
            for match in self._DOMAIN_RE.finditer(token):
                targets.append(match.group())
        return list(set(targets))

    def validate_command(self, command: list[str]) -> None:
        """Raise ScopeViolationError if any target in *command* is out of scope."""
        if not self.allowed_domains and not self.allowed_ip_networks:
            # No restrictions defined – allow everything
            return

        targets = self._extract_targets_from_command(command)
        for t in targets:
            if not self.is_in_scope(t):
                raise ScopeViolationError(
                    f"Target '{t}' is out of scope. Allowed: "
                    f"domains={self.allowed_domains}, "
                    f"ips={[str(n) for n in self.allowed_ip_networks]}"
                )
