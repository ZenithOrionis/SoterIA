"""
SoterIA -- CISO Copilot Backend
=====================================
Provides the `answer_ciso_question` coroutine that:
  1. Gathers a rich, structured data context from SQLite (stats, recent
     threats, top attacker IPs, user accounts, MITRE tactics).
  2. Injects that context into a detailed system prompt.
  3. Routes the question through the Universal LLM Gateway.
  4. Returns a clean natural-language answer string.

Architectural Law 2 is fully respected -- no direct LLM imports here.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from src.db.database import DB_PATH
from src.services.llm_gateway import query_swarm_llm

# ── Response JSON schema (single field) ─────────────────────────────
_ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer": {
            "type": "string",
            "description": "The CISO Copilot's natural language response.",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "Confidence level in the answer based on available data.",
        },
    },
    "required": ["answer", "confidence"],
    "additionalProperties": False,
}

# ── System prompt template ───────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are the CISO Copilot for SoterIA, an elite autonomous SOC platform.
You have direct access to the live security event database. Your role is to
answer questions from the CISO and security analysts with precision,
brevity, and authority.

RULES:
- Answer in 2-5 sentences maximum. Be concise and action-oriented.
- Ground every claim in the database context provided. Never hallucinate.
- If the data is insufficient to answer, say so directly.
- Use professional cybersecurity language appropriate for a CISO.
- Format key numbers and IPs in a readable way (e.g. "3 brute-force attempts
  from 91.240.118.7 in the last hour").
- If you see a pattern that warrants escalation, recommend it explicitly.

DATABASE CONTEXT:
{context}
"""


def _build_context() -> str:
    """Query SQLite and build a rich text context block for the LLM."""
    if not DB_PATH.exists():
        return "Database not found. No events have been recorded yet."

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    ctx_parts: list[str] = []

    try:
        # ── Global stats ─────────────────────────────────────────────
        row = conn.execute(
            """SELECT
                COUNT(*)                                         AS total,
                SUM(CASE WHEN threat_score > 7.0 THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN threat_score BETWEEN 4 AND 7 THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN threat_score < 4  THEN 1 ELSE 0 END) AS benign,
                ROUND(AVG(threat_score), 2)                      AS avg_score,
                ROUND(MAX(threat_score), 2)                      AS peak_score
               FROM security_events
               WHERE threat_score IS NOT NULL"""
        ).fetchone()
        if row:
            ctx_parts.append(
                f"OVERALL STATS: {row['total']} total events | "
                f"{row['critical']} critical (>7.0) | "
                f"{row['high']} high (4-7) | "
                f"{row['benign']} benign (<4) | "
                f"Avg score: {row['avg_score']} | Peak score: {row['peak_score']}"
            )

        # ── Last-hour activity ────────────────────────────────────────
        one_hour_ago = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        hour_row = conn.execute(
            """SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN threat_score > 7.0 THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN event_id IN ('4625','4688','7045') THEN 1 ELSE 0 END) AS attacks
               FROM security_events
               WHERE timestamp >= ? AND threat_score IS NOT NULL""",
            (one_hour_ago,),
        ).fetchone()
        if hour_row:
            ctx_parts.append(
                f"LAST HOUR: {hour_row['total']} events | "
                f"{hour_row['critical']} critical | "
                f"{hour_row['attacks']} attack-type events (4625/4688/7045)"
            )

        # ── Top attacker IPs ──────────────────────────────────────────
        top_ips = conn.execute(
            """SELECT source_ip, COUNT(*) AS cnt,
                      ROUND(AVG(threat_score), 2) AS avg_score
               FROM security_events
               WHERE threat_score IS NOT NULL
               GROUP BY source_ip
               ORDER BY avg_score DESC, cnt DESC
               LIMIT 8"""
        ).fetchall()
        if top_ips:
            ip_lines = ", ".join(
                f"{r['source_ip']} (x{r['cnt']}, avg={r['avg_score']})"
                for r in top_ips
            )
            ctx_parts.append(f"TOP IPs BY THREAT: {ip_lines}")

        # ── Top targeted user accounts ────────────────────────────────
        top_users = conn.execute(
            """SELECT user_account, COUNT(*) AS cnt,
                      ROUND(MAX(threat_score), 2) AS peak
               FROM security_events
               WHERE threat_score > 4.0
               GROUP BY user_account
               ORDER BY cnt DESC
               LIMIT 6"""
        ).fetchall()
        if top_users:
            user_lines = ", ".join(
                f"{r['user_account']} (x{r['cnt']}, peak={r['peak']})"
                for r in top_users
            )
            ctx_parts.append(f"MOST TARGETED ACCOUNTS: {user_lines}")

        # ── Event type distribution ───────────────────────────────────
        event_dist = conn.execute(
            """SELECT event_id, COUNT(*) AS cnt,
                      ROUND(AVG(threat_score), 2) AS avg_score
               FROM security_events
               WHERE threat_score IS NOT NULL
               GROUP BY event_id
               ORDER BY cnt DESC"""
        ).fetchall()
        if event_dist:
            dist_lines = " | ".join(
                f"EventID {r['event_id']}: {r['cnt']} occurrences (avg={r['avg_score']})"
                for r in event_dist
            )
            ctx_parts.append(f"EVENT DISTRIBUTION: {dist_lines}")

        # ── MITRE tactics observed ────────────────────────────────────
        recent_verdicts = conn.execute(
            """SELECT verdicts FROM security_events
               WHERE verdicts IS NOT NULL AND verdicts != ''
               ORDER BY timestamp DESC LIMIT 30"""
        ).fetchall()
        tactics: set[str] = set()
        for vrow in recent_verdicts:
            try:
                for v in json.loads(vrow["verdicts"]):
                    t = v.get("mitre_tactic", "")
                    if t and t != "None":
                        tactics.add(t)
            except Exception:
                pass
        if tactics:
            ctx_parts.append(f"MITRE TACTICS OBSERVED: {', '.join(sorted(tactics))}")

        # ── Last 5 critical events ────────────────────────────────────
        critical_events = conn.execute(
            """SELECT timestamp, source_ip, user_account, event_id, threat_score
               FROM security_events
               WHERE threat_score > 7.0
               ORDER BY timestamp DESC LIMIT 5"""
        ).fetchall()
        if critical_events:
            lines = []
            for e in critical_events:
                lines.append(
                    f"  [{e['timestamp'][:19]}] "
                    f"IP={e['source_ip']} User={e['user_account']} "
                    f"EventID={e['event_id']} Score={e['threat_score']:.2f}"
                )
            ctx_parts.append("RECENT CRITICAL EVENTS:\n" + "\n".join(lines))

    finally:
        conn.close()

    return "\n\n".join(ctx_parts) if ctx_parts else "No data available yet."


async def answer_ciso_question(question: str) -> dict[str, str]:
    """
    Answer a natural-language question from the CISO using live DB context.

    Returns
    -------
    dict with keys:
        ``answer``     — the natural language response string
        ``confidence`` — "high" | "medium" | "low"
        (or an ``error`` key if the gateway failed)
    """
    context = _build_context()
    system_prompt = _SYSTEM_PROMPT.format(context=context)

    result = await query_swarm_llm(
        system_prompt=system_prompt,
        user_payload=question,
        response_schema=_ANSWER_SCHEMA,
    )

    # Gateway error envelope
    if result.get("status") == "error":
        return {
            "answer": f"Copilot offline: {result.get('message', 'Unknown error')}",
            "confidence": "low",
        }

    return {
        "answer": result.get("answer", "No response generated."),
        "confidence": result.get("confidence", "medium"),
    }
