"""
SoterIA -- Boardroom Incident Report Generator
==================================================
Produces highly styled, formal Executive Incident Memorandums in Markdown format.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from src.db.database import DB_PATH

_REPORTS_DIR = DB_PATH.parent / "reports"


def generate_incident_report(log_id: str) -> Path:
    """Generate a formal markdown report for a specific incident and save to disk."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = _REPORTS_DIR / f"INCIDENT_{log_id}.md"

    # If the report already exists, return the cached path
    if report_path.exists():
        return report_path

    # Query the event from SQLite
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM security_events WHERE id = ?", (log_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"Event ID {log_id} not found in database.")
        
        event_dict = dict(row)
    finally:
        conn.close()

    # Parse JSON verdicts
    verdicts = []
    verdicts_str = event_dict.get("verdicts")
    if verdicts_str:
        try:
            verdicts = json.loads(verdicts_str)
        except Exception:
            pass

    # Extract all unique MITRE tactics found
    mitre_tactics = set()
    for v in verdicts:
        mitre = v.get("mitre_tactic", "None")
        if mitre and mitre != "None":
            mitre_tactics.add(mitre)
    
    mitre_str = ", ".join(mitre_tactics) if mitre_tactics else "N/A"
    
    # Severity string
    score = event_dict.get("threat_score", 0.0)
    severity = "CRITICAL" if score >= 7.0 else "HIGH" if score >= 5.0 else "MEDIUM" if score >= 3.0 else "LOW"
    
    # Build the report Markdown
    report_lines = [
        "**CONFIDENTIAL // FOR INTERNAL CISO REVIEW ONLY**",
        "",
        "# EXECUTIVE INCIDENT MEMORANDUM",
        "---",
        "",
        f"**INCIDENT ID:** `{log_id}`",
        f"**GENERATED:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}`",
        f"**THREAT LEVEL:** **{severity} (Score: {score:.2f}/10.00)**",
        f"**MITRE ATT&CK® TACTICS:** {mitre_str}",
        "",
        "## I. Executive Summary",
        "At the specified timeline of interception, the autonomous SoterIA SOC detected anomalous activity originating from a monitored endpoint/network. "
        "A consensus of specialized AI agents evaluated the telemetry and determined the threat score above. Immediate review of the swarm rationale is advised.",
        "",
        "## II. Timeline of Interception",
        f"- **Timestamp of Record (UTC):** `{event_dict['timestamp']}`",
        f"- **Source IP Address:** `{event_dict['source_ip']}`",
        f"- **User Account Target:** `{event_dict['user_account']}`",
        f"- **Windows Event ID:** `{event_dict['event_id']}`",
        "",
        "## III. Swarm Consensus Breakdown",
    ]
    
    if not verdicts:
        report_lines.append("> *No swarm verdicts recorded for this incident.*")
    else:
        for v in verdicts:
            agent = v.get("agent_name", "Unknown Agent")
            r_score = v.get("risk_score", 0.0)
            conf = v.get("confidence", 0.0)
            rationale = v.get("rationale", "No rationale provided.")
            
            report_lines.extend([
                f"### {agent.upper()}",
                f"- **Assessed Risk:** {r_score:.1f}/10.0",
                f"- **Confidence:** {conf:.2f}",
                f"- **Rationale:** *{rationale}*",
                ""
            ])
            
    report_lines.extend([
        "## IV. Raw Telemetry Log",
        "```text",
        event_dict.get("raw_log", "N/A").strip(),
        "```",
        "",
        "---",
        "*Report autonomously compiled by SoterIA Engine.*",
        "**DO NOT DISTRIBUTE EXTERNALLY.**"
    ])
    
    # Write report
    report_content = "\n".join(report_lines)
    report_path.write_text(report_content, encoding="utf-8")
    
    return report_path
