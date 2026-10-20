import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

MAX_ACTIVE_SCANS = 10


class QueueFullError(Exception):
    """The local queue reached its configured safety limit."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | None = None) -> None:
        configured = path or os.getenv("API_VULN_DB", "data/scanner.sqlite3")
        self.path = Path(configured)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    spec_filename TEXT NOT NULL,
                    source_spec TEXT,
                    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);
                CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status, created_at);

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    affected_operations_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id, id);
                """
            )
            # A process may have exited while a scan was running. Its source spec is retained
            # until completion so the single local worker can safely pick it up again.
            connection.execute("UPDATE scans SET status = 'queued', started_at = NULL WHERE status = 'running'")

    def create_scan(self, name: str, target_url: str, filename: str, source_spec: str) -> dict[str, Any]:
        scan_id = str(uuid.uuid4())
        created_at = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active_count = connection.execute(
                "SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')"
            ).fetchone()[0]
            if active_count >= MAX_ACTIVE_SCANS:
                raise QueueFullError("The local queue is full. Wait for a scan to finish and try again.")
            connection.execute(
                "INSERT INTO scans (id, name, target_url, spec_filename, source_spec, status, created_at) VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                (scan_id, name, target_url, filename, source_spec, created_at),
            )
        return self.get_scan(scan_id, include_findings=False)  # type: ignore[return-value]

    def claim_next_scan(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT id, source_spec FROM scans WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            changed = connection.execute(
                "UPDATE scans SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'",
                (utc_now(), row["id"]),
            ).rowcount
            connection.commit()
            return {"id": row["id"], "source_spec": row["source_spec"]} if changed else None

    def complete_scan(self, scan_id: str, findings: list[dict[str, Any]], summary: dict[str, int]) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            connection.executemany(
                """INSERT INTO findings (
                    scan_id, rule_id, title, severity, confidence, summary, impact, remediation,
                    affected_operations_json, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    scan_id, finding["rule_id"], finding["title"], finding["severity"], finding["confidence"],
                    finding["summary"], finding["impact"], finding["remediation"],
                    json.dumps(finding["affected_operations"]), json.dumps(finding["evidence"]),
                ) for finding in findings],
            )
            connection.execute(
                "UPDATE scans SET status = 'completed', completed_at = ?, source_spec = NULL, error = NULL, summary_json = ? WHERE id = ?",
                (utc_now(), json.dumps(summary), scan_id),
            )
            connection.commit()

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE scans SET status = 'failed', completed_at = ?, source_spec = NULL, error = ?, summary_json = '{}' WHERE id = ?",
                (utc_now(), error[:500], scan_id),
            )

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, name, target_url, spec_filename, status, created_at, started_at, completed_at, error, summary_json FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._scan_row(row) for row in rows]

    def get_scan(self, scan_id: str, include_findings: bool = True) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, name, target_url, spec_filename, status, created_at, started_at, completed_at, error, summary_json FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            result = self._scan_row(row)
            if include_findings:
                items = connection.execute(
                    "SELECT rule_id, title, severity, confidence, summary, impact, remediation, affected_operations_json, evidence_json FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, rule_id",
                    (scan_id,),
                ).fetchall()
                result["findings"] = [
                    {
                        "rule_id": item["rule_id"], "title": item["title"], "severity": item["severity"],
                        "confidence": item["confidence"], "summary": item["summary"], "impact": item["impact"],
                        "remediation": item["remediation"],
                        "affected_operations": json.loads(item["affected_operations_json"]),
                        "evidence": json.loads(item["evidence_json"]),
                    }
                    for item in items
                ]
            return result

    @staticmethod
    def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "name": row["name"], "target_url": row["target_url"],
            "spec_filename": row["spec_filename"], "status": row["status"],
            "created_at": row["created_at"], "started_at": row["started_at"],
            "completed_at": row["completed_at"], "error": row["error"],
            "summary": json.loads(row["summary_json"]),
        }
