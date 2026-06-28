"""
SoterIA — Intel Agent
=============================
Analyses security events against external Threat Intelligence (CTI).
Replicates CrowdStrike Falcon Intelligence capabilities.

Focus areas:
  * Checking source IPs and hashes against known MISP/OTX IoCs.
  * Elevating threat risk based on known APT campaigns.
"""

from __future__ import annotations

import logging

from src.agents.schemas import AgentVerdict, AGENT_VERDICT_SCHEMA
from src.services.llm_gateway import query_swarm_llm
from src.services.misp_client import misp_client

logger = logging.getLogger("soteria.agent.intel")

_AGENT_NAME = "intel_agent"

_SYSTEM_PROMPT = """\
You are the Threat Intelligence Agent in the SoterIA SOC.

YOUR MANDATE — analyse the security log below and evaluate ONLY:
  1. The presence of known malicious Indicators of Compromise (IoCs).
  2. If the Threat Intel Context block contains a match for an APT or Campaign, heavily elevate the risk score.

IGNORE user identity anomalies or deep endpoint internals. Other agents handle those.

Return your verdict as JSON matching the provided schema.
  - agent_name must be "intel_agent".
  - risk_score: 1.0 (benign) to 10.0 (critical).
  - confidence: 0.0 to 1.0.
  - mitre_tactic: relevant MITRE ATT&CK ID (e.g. "T1105 - Ingress Tool Transfer")
    or "None" if benign.
  - rationale: max 2 sentences explaining the IoC match.
"""

async def analyse(log_entry: dict) -> AgentVerdict:
    """Run intelligence-focused analysis on a single security event."""
    
    src_ip = log_entry.get('src_ip', 'Unknown')
    
    intel_context = ""
    # Check IP against MISP
    intel_match = misp_client.check_ioc(src_ip)
    if intel_match:
        intel_context = (
            f"\n\n[THREAT INTEL IOC MATCH]\n"
            f"External CTI confirms IP '{src_ip}' is a known IoC!\n"
            f"Campaign: {intel_match['campaign']}\n"
            f"Threat Level: {intel_match['threat_level']}\n"
            f"Description: {intel_match['description']}\n"
            f"Elevate risk score accordingly."
        )

    user_payload = (
        f"EVENT_ID: {log_entry['event_id']}\n"
        f"SOURCE_IP: {src_ip}\n"
        f"TIMESTAMP: {log_entry['timestamp']}\n"
        f"RAW_LOG:\n{log_entry['raw_log']}"
        f"{intel_context}"
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
