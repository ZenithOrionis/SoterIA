"""
SoterIA — Endpoint Agent
===============================
Analyses security events through the lens of **endpoint process
execution and service manipulation**.

Focus areas (and ONLY these):
  * Event 4688 — new process creation, especially PowerShell, cmd.exe,
    or any process downloading executables.
  * Event 7045 — new Windows service installations with suspicious
    names, paths, or auto-start configurations.
  * Suspicious file names / paths (e.g. executables in Temp directories).

This agent does NOT evaluate user accounts or network addresses.
Those are the responsibility of sibling agents.
"""

from __future__ import annotations

import logging

from src.agents.schemas import AgentVerdict, AGENT_VERDICT_SCHEMA
from src.services.llm_gateway import query_swarm_llm

logger = logging.getLogger("soteria.agent.endpoint")

_AGENT_NAME = "endpoint_agent"

_SYSTEM_PROMPT = """\
You are the Endpoint Analysis Agent in the SoterIA SOC.

YOUR MANDATE — analyse the security log below and evaluate ONLY:
  1. Event 4688 (Process Creation) — look for PowerShell, cmd.exe,
     or wscript executing with suspicious command-line arguments.
  2. Event 7045 (Service Installation) — look for unusual paths.
  3. File-name and path indicators — executables in C:\\Temp.
  4. YARA Matches (Malware Detection) — explicitly look for "YARA",
     "malware", or file integrity anomalies. If found, this is a CRITICAL threat.

For Event IDs that are NOT related to process creation, services, or malware
(e.g. 4624, 4625), your risk_score should be low (1.0-2.0) because those events
are outside your domain.

IGNORE user account privilege analysis and source IP reputation.
Other agents handle those.

Return your verdict as JSON matching the provided schema.
  - agent_name must be "endpoint_agent".
  - risk_score: 1.0 (benign) to 10.0 (critical).
  - confidence: 0.0 to 1.0.
  - mitre_tactic: relevant MITRE ATT&CK ID (e.g. "T1059.001 - PowerShell",
    "T1543.003 - Windows Service") or "None" if benign.
  - rationale: max 2 sentences.
"""


async def analyse(log_entry: dict) -> AgentVerdict:
    """Run endpoint-focused analysis on a single security event.

    Parameters
    ----------
    log_entry : dict
        A ``security_events`` row dict (must contain ``raw_log``,
        ``event_id``).

    Returns
    -------
    AgentVerdict
        Validated Pydantic model.
    """

    user_payload = (
        f"EVENT_ID: {log_entry['event_id']}\n"
        f"SOURCE_IP: {log_entry['source_ip']}\n"
        f"USER_ACCOUNT: {log_entry['user_account']}\n"
        f"TIMESTAMP: {log_entry['timestamp']}\n"
        f"RAW_LOG:\n{log_entry['raw_log']}"
    )

    result = await query_swarm_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_payload=user_payload,
        response_schema=AGENT_VERDICT_SCHEMA,
    )

    if result.get("status") == "error":
        logger.warning("LLM error in %s: %s", _AGENT_NAME, result.get("message"))
        return AgentVerdict(
            agent_name=_AGENT_NAME,
            risk_score=1.0,
            confidence=0.0,
            mitre_tactic="None",
            rationale=f"LLM unavailable — defaulting to low risk. Error: {result.get('error_code')}",
        )

    try:
        result["agent_name"] = _AGENT_NAME
        return AgentVerdict.model_validate(result)
    except Exception as exc:
        logger.error("Pydantic validation failed in %s: %s", _AGENT_NAME, exc)
        return AgentVerdict(
            agent_name=_AGENT_NAME,
            risk_score=1.0,
            confidence=0.0,
            mitre_tactic="None",
            rationale=f"Schema validation failed — defaulting to low risk. {str(exc)[:100]}",
        )
