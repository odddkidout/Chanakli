"""AutoPwn Agent — entry point for running a pentest session from the CLI."""
import asyncio
import json
import os
import sys
import uuid

from dotenv import load_dotenv

load_dotenv()


async def main() -> None:
    from core.config import Settings
    from core.orchestrator import run_pentest

    settings = Settings()

    target = os.getenv("TARGET_HOST", "pigi.in")
    session_id = str(uuid.uuid4())

    scope = {
        "domains": [d.strip() for d in os.getenv("SCOPE_DOMAINS", "pigi.in,*.pigi.in").split(",")],
        "ports": [int(p) for p in os.getenv("SCOPE_PORTS", "80,443").split(",")],
        "paths": [p.strip() for p in os.getenv("SCOPE_PATHS", "/").split(",")],
        "cidrs": [],
    }

    print(f"[AutoPwn] Starting session {session_id} against {target}")
    print(f"[AutoPwn] Scope: {scope}")

    result = await run_pentest(
        session_id=session_id,
        target=target,
        scope=scope,
        max_iterations=settings.max_iterations,
    )

    print("\n[AutoPwn] Session complete.")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
