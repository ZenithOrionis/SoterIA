"""
SoterIA — Log Ingestor
============================
Fetches pending security events from SQLite in small batches,
atomically marks them as ``processing``, and returns them as plain
Python dicts for downstream agent consumption.

Design notes
------------
* Batch size capped at 5 to keep agent context windows lean.
* Status transition is ``pending → processing`` inside a single
  transaction so no two workers ever double-process the same event.
* Returns ``list[dict]`` — no ORM objects leak outside this module.
"""

from __future__ import annotations

from src.db.database import get_connection


def fetch_pending_logs(batch_size: int = 5) -> list[dict]:
    """Fetch up to *batch_size* pending events, mark them ``processing``, return as dicts.

    Returns
    -------
    list[dict]
        Each dict mirrors a ``security_events`` row with keys:
        ``id``, ``timestamp``, ``source_ip``, ``user_account``,
        ``event_id``, ``raw_log``, ``status``, ``threat_score``.
        Empty list if nothing is pending.
    """
    conn = get_connection()
    try:
        # ── 1. Read pending rows (oldest first) ─────────────────────
        cursor = conn.execute(
            """
            SELECT id, timestamp, source_ip, user_account,
                   event_id, raw_log, status, threat_score
            FROM   security_events
            WHERE  status = 'pending'
            ORDER  BY timestamp ASC
            LIMIT  ?
            """,
            (batch_size,),
        )
        rows = cursor.fetchall()

        if not rows:
            return []

        # ── 2. Atomically flip status to 'processing' ───────────────
        ids = [row["id"] for row in rows]
        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE security_events SET status = 'processing' WHERE id IN ({placeholders})",
            ids,
        )
        conn.commit()

        # ── 3. Return plain dicts ────────────────────────────────────
        return [dict(row) for row in rows]

    finally:
        conn.close()
