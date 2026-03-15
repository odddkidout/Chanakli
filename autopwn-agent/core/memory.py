from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Optional

import structlog

from models.finding import Finding, VerifiedFinding

if TYPE_CHECKING:
    import redis as redis_module
    import chromadb as chroma_module

logger = structlog.get_logger()

SESSION_TTL = 86400  # 24 hours


class AttackMemory:
    """Manages session memory (Redis), technique memory (ChromaDB), and findings (PostgreSQL)."""

    def __init__(
        self,
        redis_client: Any,
        chroma_client: Any,
        db_conn: Optional[Any] = None,
    ):
        self._redis = redis_client
        self._chroma = chroma_client
        self._db = db_conn

        # ChromaDB collection for technique recall
        try:
            self._technique_collection = self._chroma.get_or_create_collection(
                "techniques"
            )
        except Exception:
            self._technique_collection = None

    # ------------------------------------------------------------------
    # Session memory – Redis
    # ------------------------------------------------------------------

    def save_session_state(self, session_id: str, state: dict) -> None:
        key = f"session:{session_id}:state"
        self._redis.setex(key, SESSION_TTL, json.dumps(state, default=str))
        logger.info("session_state_saved", session_id=session_id)

    def load_session_state(self, session_id: str) -> Optional[dict]:
        key = f"session:{session_id}:state"
        data = self._redis.get(key)
        if data is None:
            return None
        return json.loads(data)

    def log_command(self, session_id: str, command: list[str]) -> None:
        """Append an executed command to the session's execution log."""
        import time

        key = f"session:{session_id}:exec_log"
        entry = json.dumps({"ts": time.time(), "cmd": command})
        self._redis.rpush(key, entry)
        self._redis.expire(key, SESSION_TTL)

    def get_execution_log(self, session_id: str) -> list[dict]:
        key = f"session:{session_id}:exec_log"
        entries = self._redis.lrange(key, 0, -1)
        return [json.loads(e) for e in entries]

    # ------------------------------------------------------------------
    # Technique memory – ChromaDB
    # ------------------------------------------------------------------

    def remember_successful_technique(
        self, tech_stack: dict, technique: dict, finding: Finding
    ) -> None:
        if self._technique_collection is None:
            return
        doc_id = f"{finding.session_id}:{finding.finding_id}"
        document = json.dumps(
            {
                "tech_stack": tech_stack,
                "technique": technique,
                "finding_type": finding.type,
                "severity": finding.severity,
            }
        )
        metadata = {
            "tech_stack_str": json.dumps(tech_stack),
            "finding_type": finding.type,
            "severity": finding.severity,
        }
        self._technique_collection.upsert(
            ids=[doc_id],
            documents=[document],
            metadatas=[metadata],
        )
        logger.info("technique_remembered", doc_id=doc_id)

    def get_proven_techniques(self, tech_stack: dict) -> list[dict]:
        """Return techniques that worked on similar tech stacks, ranked by similarity."""
        if self._technique_collection is None:
            return []
        query_text = json.dumps(tech_stack)
        try:
            results = self._technique_collection.query(
                query_texts=[query_text],
                n_results=10,
            )
            techniques: list[dict] = []
            for doc in results.get("documents", [[]])[0]:
                try:
                    techniques.append(json.loads(doc))
                except json.JSONDecodeError:
                    pass
            return techniques
        except Exception as exc:
            logger.warning("technique_query_failed", error=str(exc))
            return []

    # ------------------------------------------------------------------
    # Finding storage – PostgreSQL
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        if self._db is None:
            return
        with self._db.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    task_id TEXT,
                    type TEXT,
                    title TEXT,
                    endpoint TEXT,
                    parameter TEXT,
                    payload TEXT,
                    evidence TEXT,
                    severity TEXT,
                    confidence REAL,
                    requires_auth BOOLEAN,
                    cvss_score REAL,
                    cwe_id TEXT,
                    discovered_at TIMESTAMPTZ,
                    tool_used TEXT,
                    raw_output TEXT,
                    verified BOOLEAN,
                    verification_runs INT,
                    false_positive_indicators JSONB,
                    exploitation_steps JSONB,
                    chain_opportunities JSONB,
                    remediation TEXT
                )
                """
            )
        self._db.commit()

    def save_finding(self, session_id: str, finding: VerifiedFinding) -> None:
        if self._db is None:
            logger.warning("db_not_configured", action="save_finding")
            return
        self._ensure_schema()
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    finding_id, session_id, task_id, type, title, endpoint,
                    parameter, payload, evidence, severity, confidence,
                    requires_auth, cvss_score, cwe_id, discovered_at, tool_used,
                    raw_output, verified, verification_runs,
                    false_positive_indicators, exploitation_steps,
                    chain_opportunities, remediation
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s
                )
                ON CONFLICT (finding_id) DO UPDATE SET
                    verified = EXCLUDED.verified,
                    verification_runs = EXCLUDED.verification_runs,
                    confidence = EXCLUDED.confidence
                """,
                (
                    finding.finding_id,
                    session_id,
                    finding.task_id,
                    finding.type,
                    finding.title,
                    finding.endpoint,
                    finding.parameter,
                    finding.payload,
                    finding.evidence,
                    finding.severity,
                    finding.confidence,
                    finding.requires_auth,
                    finding.cvss_score,
                    finding.cwe_id,
                    finding.discovered_at,
                    finding.tool_used,
                    finding.raw_output,
                    finding.verified,
                    finding.verification_runs,
                    json.dumps(finding.false_positive_indicators),
                    json.dumps(finding.exploitation_steps),
                    json.dumps(finding.chain_opportunities),
                    finding.remediation,
                ),
            )
        self._db.commit()

    def get_session_findings(self, session_id: str) -> list[VerifiedFinding]:
        if self._db is None:
            return []
        self._ensure_schema()
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE session_id = %s ORDER BY discovered_at",
                (session_id,),
            )
            rows = cur.fetchall()
        findings: list[VerifiedFinding] = []
        for row in rows:
            (
                finding_id,
                session_id_,
                task_id,
                ftype,
                title,
                endpoint,
                parameter,
                payload,
                evidence,
                severity,
                confidence,
                requires_auth,
                cvss_score,
                cwe_id,
                discovered_at,
                tool_used,
                raw_output,
                verified,
                verification_runs,
                fp_indicators,
                exp_steps,
                chain_opps,
                remediation,
            ) = row
            findings.append(
                VerifiedFinding(
                    finding_id=finding_id,
                    session_id=session_id_,
                    task_id=task_id or "",
                    type=ftype or "",
                    title=title or "",
                    endpoint=endpoint or "",
                    parameter=parameter,
                    payload=payload,
                    evidence=evidence or "",
                    severity=severity or "low",
                    confidence=float(confidence or 0.0),
                    requires_auth=bool(requires_auth),
                    cvss_score=float(cvss_score) if cvss_score else None,
                    cwe_id=cwe_id,
                    discovered_at=discovered_at,
                    tool_used=tool_used or "",
                    raw_output=raw_output or "",
                    verified=bool(verified),
                    verification_runs=int(verification_runs or 0),
                    false_positive_indicators=json.loads(fp_indicators or "[]"),
                    exploitation_steps=json.loads(exp_steps or "[]"),
                    chain_opportunities=json.loads(chain_opps or "[]"),
                    remediation=remediation or "",
                )
            )
        return findings
