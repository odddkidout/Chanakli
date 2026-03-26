# Chanakli — AutoPwn Agent

An autonomous penetration testing AI system powered by LangGraph, FastAPI, and LiteLLM.

## Overview

AutoPwn Agent orchestrates a full pentest pipeline against a scoped target using a 7-node LangGraph state machine:

```
recon → planning → execution → verification → chain_analysis → reflection → done
```

It uses dual LLM agents (Auditor for strategy, Executor for tool operation) and a suite of security scanners.

## Quick Start — Testing Against pigi.in

```bash
cd autopwn-agent

# 1. Copy and configure environment
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY (or configure LiteLLM with your preferred model)

# 2. Start infrastructure
docker-compose up -d redis postgres chromadb litellm

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run the agent against pigi.in
python main.py
```

The agent will:
1. **Recon** — discover subdomains of pigi.in via crt.sh, probe live hosts, detect technologies
2. **Plan** — LLM generates a prioritised attack plan based on the attack surface
3. **Execute** — runs security tools (nmap, nuclei, etc.) within the pigi.in scope
4. **Verify** — reproducibility checks eliminate false positives
5. **Chain** — builds an exploit dependency graph and identifies kill chains
6. **Reflect** — decides whether another iteration is needed
7. **Report** — structured Markdown/JSON report

## API Usage

```bash
# Start the API server
uvicorn api.server:app --host 0.0.0.0 --port 8080

# Start a pentest session against pigi.in
curl -X POST http://localhost:8080/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "target": "pigi.in",
    "scope": {
      "domains": ["pigi.in", "*.pigi.in"],
      "ports": [80, 443],
      "paths": ["/"],
      "cidrs": []
    },
    "max_iterations": 5
  }'

# Poll session status
curl http://localhost:8080/sessions/<session_id>

# Get findings
curl http://localhost:8080/sessions/<session_id>/findings

# Generate a Markdown report
curl -X POST http://localhost:8080/sessions/<session_id>/report \
  -H "Content-Type: application/json" \
  -d '{"format": "markdown"}'
```

## Scope Enforcement

All commands are validated against the configured scope before execution. Out-of-scope targets raise a `ScopeViolationError` and are never executed.

The default scope for pigi.in testing:
- **Domains:** `pigi.in`, `*.pigi.in`
- **Ports:** `80`, `443`
- **CIDRs:** (configure after resolving pigi.in's IPs)

## Architecture

| Component | Description |
|-----------|-------------|
| `core/orchestrator.py` | LangGraph 7-node state machine |
| `core/state.py` | `PentestState` TypedDict |
| `core/scope.py` | Scope enforcement + `ScopeViolationError` |
| `core/memory.py` | Redis session memory |
| `agents/auditor.py` | Strategic LLM agent (planning, reflection) |
| `agents/executor.py` | Tool-operating LLM agent |
| `engines/recon_engine.py` | 4-phase recon pipeline |
| `engines/verifier.py` | Finding reproducibility verification |
| `engines/chain_engine.py` | Exploit dependency graph + kill chains |
| `tools/safe_executor.py` | Sandboxed subprocess runner |
| `api/server.py` | FastAPI control plane |
| `reports/generator.py` | Markdown + JSON report export |

## Tool Support

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service detection |
| nuclei | Template-based vulnerability scanning |
| sqlmap | SQL injection testing |
| ffuf | Directory/endpoint fuzzing |
| subfinder | Subdomain enumeration |
| httpx | HTTP probing, tech detection |
| katana | Web crawling |
| dalfox | XSS scanning |
| arjun | Hidden parameter discovery |
| jwt_tool | JWT vulnerability testing |

> **⚠️ Warning:** This tool is for **authorized testing only**. Only run against targets you own or have explicit written permission to test. The scope enforcement system restricts all tool execution to the configured target (pigi.in by default).