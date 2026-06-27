"""
SoterIA — Network Agent
==============================
Analyses security events through the lens of **network indicators**.

Focus areas (and ONLY these):
  * Source IP addresses — RFC-1918 internal vs. known-bad external IPs.
  * Subnet anomalies — e.g. an external IP hitting an internal-only service.
  * Port behaviour noted in the raw log.

This agent does NOT evaluate user accounts, process execution, or
service installations.  Those are the responsibility of sibling agents.
"""

from __future__ import annotations

import logging

from src.agents.schemas import AgentVerdict, AGENT_VERDICT_SCHEMA
from src.services.llm_gateway import query_swarm_llm

logger = logging.getLogger("soteria.agent.network")

_AGENT_NAME = "network_agent"

_SYSTEM_PROMPT = """\
You are the Network Analysis Agent in the SoterIA SOC.

YOUR MANDATE — analyse the security log below and evaluate ONLY:
  1. Source IP address — is it internal (10.x.x.x, 172.16-31.x.x,
     192.168.x.x) or external?  External IPs targeting privileged
     logons are high risk.
  2. Port numbers — unusual source ports or well-known attack ports.
  3. Subnet context — does the IP belong to a suspicious AS or
     known threat-intel range?  Use your training knowledge of
     common C2 infrastructure IP ranges.

IGNORE user account names, process execution, service installations,
and file paths.  Other agents handle those.

Return your verdict as JSON matching the provided schema.
  - agent_name must be "network_agent".
  - risk_score: 1.0 (benign) to 10.0 (critical).
  - confidence: 0.0 to 1.0.
  - mitre_tactic: relevant MITRE ATT&CK ID (e.g. "T1190 - Exploit Public-Facing Application")
    or "None" if benign.
  - rationale: max 2 sentences.
"""


async def analyse(log_entry: dict) -> AgentVerdict:
    """Run network-focused analysis on a single security event.

    Parameters
    ----------
    log_entry : dict
        A ``security_events`` row dict (must contain ``raw_log``,
        ``source_ip``, ``event_id``).

    Returns
    -------
    AgentVerdict
        Validated Pydantic model.
    """

    user_payload = (
        f"EVENT_ID: {log_entry['event_id']}\n"
        f"SOURCE_IP: {log_entry['source_ip']}\n"
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
            rationale=f"Schema validation failed — defaulting to low risk. {exc}",
        )
