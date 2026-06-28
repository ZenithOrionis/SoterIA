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
        # ── 0. Poll Elasticsearch for new alerts ────────────────────
        try:
            import json
            import urllib3
            from elasticsearch import Elasticsearch
            from src.config.settings import get_settings
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            stgs = get_settings()
            
            es = Elasticsearch(
                stgs.ES_URL,
                basic_auth=(stgs.ES_USER, stgs.ES_PASS),
                verify_certs=False
            )
            
            # Query for high severity alerts (rule.level >= 10) not yet handled
            query = {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 10}}}
                    ],
                    "must_not": [
                        {"term": {"orchestrator.handled": True}}
                    ]
                }
            }
            
            res = es.search(index="wazuh-alerts-*", query=query, size=10)
            hits = res.get("hits", {}).get("hits", [])
            
            for hit in hits:
                doc_id = hit["_id"]
                index = hit["_index"]
                src = hit["_source"]
                
                # Map ECS to SoterIA schema
                timestamp = src.get("@timestamp", "")
                event_id = src.get("rule", {}).get("id", "0")
                
                # Extract IP and User
                source_ip = "Unknown"
                if "source" in src and "ip" in src["source"]:
                    source_ip = src["source"]["ip"]
                elif "agent" in src and "ip" in src["agent"]:
                    source_ip = src["agent"]["ip"]
                    
                user_account = "Unknown"
                if "user" in src and "name" in src["user"]:
                    user_account = src["user"]["name"]
                elif "data" in src and "win" in src["data"] and "eventdata" in src["data"]["win"]:
                    user_account = src["data"]["win"]["eventdata"].get("targetUserName", "Unknown")
                    
                raw_log_str = json.dumps(src)
                
                # Insert into SQLite
                conn.execute(
                    """
                    INSERT INTO security_events (timestamp, source_ip, user_account, event_id, raw_log, status)
                    VALUES (?, ?, ?, ?, ?, 'pending')
                    """,
                    (timestamp, source_ip, user_account, event_id, raw_log_str)
                )
                
                # Mark handled in ES
                es.update(
                    index=index,
                    id=doc_id,
                    doc={"orchestrator": {"handled": True}}
                )
            
            conn.commit()
        except Exception as e:
            print(f"[!] ES Poll Error: {e}")
            
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
