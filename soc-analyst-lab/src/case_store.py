"""Tiny SQLite case store for local SOC lab investigations."""
from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DB = Path("data/cases.sqlite3")
VALID_STATUSES = {"open", "investigating", "escalated", "closed"}

def finding_key(finding: dict[str, Any]) -> str:
    """Return the canonical key shared by dashboard and case-store operations."""
    return "|".join(str(finding.get(k, "") or "") for k in ("rule_id", "host", "account", "timestamp"))

@contextmanager
def session(db_path: Path = DEFAULT_DB):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                finding_key TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                host TEXT,
                account TEXT,
                severity TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                analyst TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def upsert_finding(finding: dict[str, Any], db_path: Path = DEFAULT_DB) -> None:
    key = finding_key(finding)
    missing = [field for field in ("rule_id", "title", "timestamp") if not finding.get(field)]
    if missing:
        raise ValueError("Finding is missing required field(s): " + ", ".join(missing))
    with session(db_path) as conn:
        conn.execute("""
            INSERT INTO cases(finding_key, rule_id, title, host, account, severity)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_key) DO UPDATE SET
              title=excluded.title, severity=excluded.severity
        """, (key, finding["rule_id"], finding["title"], finding.get("host", ""),
              finding.get("account", ""), finding.get("severity", "low")))

def list_cases(db_path: Path = DEFAULT_DB) -> list[dict[str, Any]]:
    with session(db_path) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM cases ORDER BY updated_at DESC, severity")]

def update_case(finding_key: str, status: str, analyst: str, notes: str,
                db_path: Path = DEFAULT_DB) -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    with session(db_path) as conn:
        cursor = conn.execute("""
            UPDATE cases SET status=?, analyst=?, notes=?, updated_at=CURRENT_TIMESTAMP
            WHERE finding_key=?
        """, (status, analyst, notes, finding_key))
        if cursor.rowcount == 0:
            raise ValueError("Case not found; refresh the dashboard and try again.")
