#!/usr/bin/env python3
"""AutoPwn Agent — entry point."""
from __future__ import annotations

import argparse
import sys

import structlog
import uvicorn

logger = structlog.get_logger()


def _run_api(host: str = "0.0.0.0", port: int = 8000) -> None:
    logger.info("starting_api", host=host, port=port)
    uvicorn.run("api.server:app", host=host, port=port, reload=False)


def _run_cli(target: str, scope_json: str, max_iterations: int) -> None:
    import json
    from core.orchestrator import run_pentest
    from reports.generator import ReportGenerator

    scope = json.loads(scope_json)
    logger.info("cli_pentest_start", target=target)
    final_state = run_pentest(target=target, scope=scope, max_iterations=max_iterations)
    generator = ReportGenerator()
    report = generator.generate(dict(final_state), fmt="markdown")
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(description="AutoPwn Agent")
    subparsers = parser.add_subparsers(dest="command")

    # API server sub-command
    api_parser = subparsers.add_parser("api", help="Start the FastAPI control server")
    api_parser.add_argument("--host", default="0.0.0.0")
    api_parser.add_argument("--port", type=int, default=8000)

    # CLI pentest sub-command
    cli_parser = subparsers.add_parser("run", help="Run a pentest from the command line")
    cli_parser.add_argument("target", help="Target domain or IP")
    cli_parser.add_argument(
        "--scope",
        default='{"allowed_domains": [], "allowed_ips": []}',
        help="Scope JSON string",
    )
    cli_parser.add_argument("--max-iterations", type=int, default=50)

    args = parser.parse_args()

    if args.command == "api":
        _run_api(host=args.host, port=args.port)
    elif args.command == "run":
        _run_cli(args.target, args.scope, args.max_iterations)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
