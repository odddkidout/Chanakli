from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.wrappers.base import BaseToolWrapper

if TYPE_CHECKING:
    from models.task import AttackTask


class JwtToolWrapper(BaseToolWrapper):
    """
    Wrapper for jwt_tool (https://github.com/ticarpi/jwt_tool).
    Tests: alg:none, weak HMAC secret, kid injection, jwks spoofing.
    """

    name = "jwt_tool"
    binary = "jwt_tool"

    def build_command(self, task: "AttackTask") -> list[str]:
        # Expect target_endpoint to contain the JWT token
        # tool_flags may contain additional options
        token = task.target_endpoint
        cmd = ["jwt_tool", token, "-M", "at"]  # -M at = all tests
        if task.tool_flags:
            cmd.extend(task.tool_flags.split())
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        findings: list[dict] = []
        combined = stdout + stderr

        # Detect algorithm confusion / alg:none
        if re.search(r"CRITICAL.*Algorithm set to none", combined, re.IGNORECASE):
            token_match = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.", combined)
            findings.append(
                {
                    "type": "jwt",
                    "title": "JWT alg:none bypass",
                    "severity": "critical",
                    "detail": "Algorithm header can be set to 'none', bypassing signature verification.",
                    "payload": token_match.group(0) if token_match else "",
                }
            )

        # Detect weak secret
        if re.search(r"secret.*found|key.*cracked|HMAC.*weak", combined, re.IGNORECASE):
            secret_match = re.search(r"Key: (.+)", combined)
            findings.append(
                {
                    "type": "jwt",
                    "title": "JWT Weak HMAC Secret",
                    "severity": "critical",
                    "detail": "Weak HMAC signing secret discovered.",
                    "secret": secret_match.group(1).strip() if secret_match else "",
                }
            )

        # Detect kid injection
        if re.search(r"kid.*inject|SQL.*kid", combined, re.IGNORECASE):
            findings.append(
                {
                    "type": "jwt",
                    "title": "JWT kid Header Injection",
                    "severity": "high",
                    "detail": "kid header parameter is injectable.",
                }
            )

        # Detect JWKS spoofing
        if re.search(r"jwks.*spoof|jku.*inject", combined, re.IGNORECASE):
            findings.append(
                {
                    "type": "jwt",
                    "title": "JWT JWKS Spoofing",
                    "severity": "critical",
                    "detail": "jku/x5u header can be tampered to point to attacker-controlled JWKS.",
                }
            )

        return findings
