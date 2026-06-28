"""
SoterIA -- Tribunal (Swarm Consensus Engine)
==================================================
**Architectural Law 3 enforcement point.**

The Tribunal:
  1. Fires all three specialist agents **concurrently** via
     ``asyncio.gather()``.
  2. Collects their ``AgentVerdict`` Pydantic models.
  3. Computes the **final threat score** using deterministic Python
     math -- no LLM is involved in the scoring step.
  4. Persists the result back to SQLite.

Scoring formula
---------------
    weighted_sum = sum(agent.risk_score * agent.confidence)  for each agent
    final_score  = weighted_sum / number_of_agents

This gives higher-confidence agents more influence while normalising
across the swarm size.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.agents import identity_agent, network_agent, endpoint_agent, intel_agent, vuln_agent
from src.agents.schemas import AgentVerdict
from src.db.database import update_event_verdict
from src.services.active_response import trigger_firewall_drop, trigger_kill_process

logger = logging.getLogger("soteria.tribunal")

async def evaluate_log(log_entry: dict[str, Any]) -> dict[str, Any]:
    # -- 1. Fan-out: all 5 agents run concurrently ---------------------
    identity_verdict, network_verdict, endpoint_verdict, intel_verdict, vuln_verdict = await asyncio.gather(
        identity_agent.analyse(log_entry),
        network_agent.analyse(log_entry),
        endpoint_agent.analyse(log_entry),
        intel_agent.analyse(log_entry),
        vuln_agent.analyse(log_entry),
    )

    verdicts: list[AgentVerdict] = [
        identity_verdict,
        network_verdict,
        endpoint_verdict,
        intel_verdict,
        vuln_verdict,
    ]

    # -- 2. Deterministic scoring (Law 3) ------------------------------
    weighted_sum = sum(v.risk_score * v.confidence for v in verdicts)
    final_score = round(weighted_sum / len(verdicts), 2)

    # Clamp to [1.0, 10.0] for safety
    final_score = max(1.0, min(10.0, final_score))

    import json
    update_event_verdict(
        event_id=log_entry["id"],
        threat_score=final_score,
        status="analysed",
        verdicts=json.dumps([v.model_dump() for v in verdicts]),
    )

    if final_score >= 7.0:
        logger.info(f"Critical threat score reached ({final_score}). Triggering autonomous containment.")
        
        # Determine appropriate Active Response
        raw_log_str = log_entry.get("raw_log", "")
        
        # If it's a YARA or endpoint process threat, kill the process
        if "YARA" in raw_log_str or "malware" in raw_log_str.lower() or endpoint_verdict.risk_score >= 8.0:
            # Attempt to extract agent_id and PID from raw log
            agent_id = "000" # fallback
            pid = None
            try:
                raw_json = json.loads(raw_log_str)
                if "agent" in raw_json and "id" in raw_json["agent"]:
                    agent_id = raw_json["agent"]["id"]
                # Try to find PID
                if "data" in raw_json and "win" in raw_json["data"] and "eventdata" in raw_json["data"]["win"]:
                    pid = raw_json["data"]["win"]["eventdata"].get("processId")
                elif "process" in raw_json and "pid" in raw_json["process"]:
                    pid = raw_json["process"]["pid"]
            except Exception:
                pass
                
            if pid:
                trigger_kill_process(agent_id, str(pid))
            else:
                logger.warning("Could not extract PID for kill-process, falling back to firewall-drop...")
                trigger_firewall_drop(log_entry.get("source_ip"))
        else:
            # Default to firewall drop against the attacker IP
            trigger_firewall_drop(log_entry.get("source_ip"))

    # -- 4. Build summary ----------------------------------------------
    summary = {
        "event_id": log_entry["id"],
        "windows_event_id": log_entry["event_id"],
        "final_score": final_score,
        "verdicts": [v.model_dump() for v in verdicts],
    }

    _log_summary(summary)
    return summary


def _log_summary(summary: dict) -> None:
    """Pretty-print a tribunal result to the console."""
    eid = summary["windows_event_id"]
    score = summary["final_score"]

    if score >= 7.0:
        severity = "CRITICAL"
        icon = "[!!!]"
    elif score >= 5.0:
        severity = "HIGH"
        icon = "[!!]"
    elif score >= 3.0:
        severity = "MEDIUM"
        icon = "[!]"
    else:
        severity = "LOW"
        icon = "[.]"

    print(f"\n  {icon} CONSENSUS SCORE: {score:.2f}/10.00  ({severity})")
    print(f"  " + "-" * 58)

    for v in summary["verdicts"]:
        mitre = v["mitre_tactic"]
        mitre_str = f"  MITRE={mitre}" if mitre != "None" else ""
        print(
            f"      {v['agent_name']:<18}  "
            f"risk={v['risk_score']:<5.1f}  "
            f"conf={v['confidence']:<4.2f}"
            f"{mitre_str}"
        )

    print(f"  " + "-" * 58)
