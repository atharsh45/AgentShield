"""SQLite-backed audit and one-time human-approval storage.

For a multi-instance production deployment, replace SQLite with a managed database
and use transactions/constraints appropriate to that deployment.
"""
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "agentshield_audit.sqlite3"
DB_PATH = Path(os.getenv("AGENTSHIELD_DB_PATH", str(DEFAULT_DB))).expanduser()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level="IMMEDIATE")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            caller_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            decision TEXT NOT NULL,
            rule_decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            ml_json TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            caller_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            event_id INTEGER,
            status TEXT NOT NULL DEFAULT 'PENDING',
            decided_at TEXT,
            decided_by TEXT,
            result_json TEXT,
            FOREIGN KEY(event_id) REFERENCES audit_events(id)
        )""")


def add_event(event: dict[str, Any]) -> dict[str, Any]:
    init_db()
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO audit_events(timestamp, caller_id, action, resource, decision, rule_decision, reason, ml_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event["timestamp"], event["caller_id"], event["action"], event["resource"],
             event["decision"], event["rule_decision"], event["reason"], json.dumps(event["ml"])),
        )
        event["id"] = int(cursor.lastrowid)
    return event


def create_approval(*, created_at: str, caller_id: str, tool: str, action: str,
                    resource: str, event_id: int | None) -> dict[str, Any]:
    init_db()
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO approval_requests(created_at, caller_id, tool, action, resource, event_id) VALUES (?, ?, ?, ?, ?, ?)",
            (created_at, caller_id, tool, action, resource, event_id),
        )
        return {"id": int(cursor.lastrowid), "created_at": created_at, "caller_id": caller_id,
                "tool": tool, "action": action, "resource": resource, "event_id": event_id,
                "status": "PENDING"}


def get_approvals(limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM approval_requests ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
    return [{"id": r["id"], "created_at": r["created_at"], "caller_id": r["caller_id"],
             "tool": r["tool"], "action": r["action"], "resource": r["resource"],
             "event_id": r["event_id"], "status": r["status"], "decided_at": r["decided_at"],
             "decided_by": r["decided_by"]} for r in rows]


def claim_approval(approval_id: int, decided_at: str, decided_by: str) -> dict[str, Any] | None:
    """Atomically change PENDING to APPROVED; prevents replay/double execution."""
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM approval_requests WHERE id=?", (approval_id,)).fetchone()
        if row is None or row["status"] != "PENDING":
            return None
        cursor = conn.execute(
            "UPDATE approval_requests SET status='APPROVED', decided_at=?, decided_by=? WHERE id=? AND status='PENDING'",
            (decided_at, decided_by, approval_id),
        )
        if cursor.rowcount != 1:
            return None
        return {"id": row["id"], "caller_id": row["caller_id"], "tool": row["tool"],
                "action": row["action"], "resource": row["resource"], "event_id": row["event_id"]}


def finish_approval(approval_id: int, status: str, result: dict[str, Any]) -> None:
    init_db()
    with _connect() as conn:
        conn.execute("UPDATE approval_requests SET status=?, result_json=? WHERE id=?",
                     (status, json.dumps(result), approval_id))


def get_events(limit: int = 300) -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
    return [{"id": r["id"], "timestamp": r["timestamp"], "caller_id": r["caller_id"],
             "action": r["action"], "resource": r["resource"], "decision": r["decision"],
             "rule_decision": r["rule_decision"], "reason": r["reason"], "ml": json.loads(r["ml_json"])} for r in rows]


def get_stats() -> dict[str, int]:
    items = get_events(1000)
    return {"total": len(items), "allowed": sum(e["decision"] == "ALLOW" for e in items),
            "blocked": sum(e["decision"] == "BLOCK" for e in items),
            "review": sum(e["decision"] == "REVIEW" for e in items),
            "anomalies": sum(bool(e["ml"].get("is_anomaly")) for e in items)}


def clear_events() -> None:
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM approval_requests")
        conn.execute("DELETE FROM audit_events")
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('audit_events','approval_requests')")
