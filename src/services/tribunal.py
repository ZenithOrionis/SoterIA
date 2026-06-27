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

from src.agents import identity_agent, network_agent, endpoint_agent
from src.agents.schemas import AgentVerdict
from src.db.database import update_event_verdict

logger = logging.getLogger("soteria.tribunal")


async def evaluate_log(log_entry: dict[str, Any]) -> dict[str, Any]:
    """Run the full swarm consensus pipeline on a single security event.

    Parameters
    ----------
    log_entry : dict
        A ``security_events`` row dict as returned by
        ``fetch_pending_logs()``.

    Returns
    -------
    dict
        Summary with keys: ``event_id``, ``windows_event_id``,
        ``final_score``, ``verdicts`` (list of verdict dicts).
    """

    # -- 1. Fan-out: all 3 agents run concurrently ---------------------
    identity_verdict, network_verdict, endpoint_verdict = await asyncio.gather(
        identity_agent.analyse(log_entry),
        network_agent.analyse(log_entry),
        endpoint_agent.analyse(log_entry),
    )

    verdicts: list[AgentVerdict] = [
        identity_verdict,
        network_verdict,
        endpoint_verdict,
    ]

    # -- 2. Deterministic scoring (Law 3) ------------------------------
    #    weighted_sum = sum(score * confidence)
    #    final_score  = weighted_sum / N
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
