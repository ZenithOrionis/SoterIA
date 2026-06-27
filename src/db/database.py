"""
SoterIA — SQLite Database Layer
=====================================
Owns the single SQLite connection and the ``security_events`` schema.

Design notes
------------
* **Law 1 compliance** — SQLite is the only persistence layer.
* Uses stdlib ``sqlite3`` — zero external dependencies.
* ``init_db()`` is idempotent (``CREATE TABLE IF NOT EXISTS``).
* Every public function acquires and releases its own connection so callers
  never have to think about cursor lifecycle.
* The DB file lives at ``data/soc_logs.db`` relative to the project root.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_DIR = _PROJECT_ROOT / "data"
DB_PATH = DB_DIR / "soc_logs.db"

# ── SQL ──────────────────────────────────────────────────────────────

CREATE_SECURITY_EVENTS = """\
CREATE TABLE IF NOT EXISTS security_events (
    id            TEXT PRIMARY KEY,          -- UUID-4 as string
    timestamp     TEXT NOT NULL,             -- ISO-8601 UTC
    source_ip     TEXT NOT NULL,
    user_account  TEXT NOT NULL,
    event_id      INTEGER NOT NULL,          -- Windows Event ID
    raw_log       TEXT NOT NULL,             -- Full EVTX-style log body
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | processing | analysed
    threat_score  REAL,                      -- NULL until scored
    verdicts      TEXT                       -- JSON array of AgentVerdict dicts
);
"""


# ── Public API ───────────────────────────────────────────────────────


def get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection with row-factory set to ``sqlite3.Row``."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")  # safe for concurrent reads
    return conn


def init_db() -> None:
    """Create all tables if they do not already exist.  Idempotent."""
    conn = get_connection()
    try:
        conn.execute(CREATE_SECURITY_EVENTS)
        conn.commit()
    finally:
        conn.close()


def insert_event(
    *,
    event_id: str,
    timestamp: str,
    source_ip: str,
    user_account: str,
    windows_event_id: int,
    raw_log: str,
    status: str = "pending",
    threat_score: float | None = None,
) -> None:
    """Insert a single security event row."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO security_events
                (id, timestamp, source_ip, user_account, event_id, raw_log, status, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, timestamp, source_ip, user_account, windows_event_id, raw_log, status, threat_score),
        )
        conn.commit()
    finally:
        conn.close()


def count_events() -> int:
    """Return total row count in ``security_events``."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM security_events").fetchone()
        return row["cnt"]  # type: ignore[index]
    finally:
        conn.close()


def update_event_verdict(event_id: str, threat_score: float, status: str = "analysed", verdicts: str | None = None) -> None:
    """Set the final threat score and status for a processed event.

    Parameters
    ----------
    event_id : str
        The UUID primary key of the ``security_events`` row.
    threat_score : float
        Deterministic score computed by the Tribunal.
    status : str
        New status value (default ``'analysed'``).
    verdicts : str | None
        JSON serialized list of agent verdicts.
    """
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE security_events SET threat_score = ?, status = ?, verdicts = ? WHERE id = ?",
            (threat_score, status, verdicts, event_id),
        )
        conn.commit()
    finally:
        conn.close()

