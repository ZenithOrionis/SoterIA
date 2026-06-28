"""
SoterIA — Vulnerability Agent (Falcon Spotlight)
===============================
Analyzes security events specifically looking for CVE disclosures, 
unpatched software, and vulnerability detector alerts.

Focus areas:
  * Vulnerability detector events (Wazuh rule group 'vulnerability-detector')
  * Events detailing unpatched software or outdated packages.
"""

from __future__ import annotations

import logging
import json
from typing import Any

from src.agents.schemas import AgentVerdict, AGENT_VERDICT_SCHEMA
from src.services.llm_gateway import query_swarm_llm

logger = logging.getLogger("soteria.agent.vuln")

_AGENT_NAME = "vuln_agent"

_SYSTEM_PROMPT = """\
You are the Vulnerability Analysis Agent in the SoterIA SOC (Mimicking Falcon Spotlight).

YOUR MANDATE — analyse the security log below and evaluate ONLY:
  1. Vulnerability Detection — explicitly look for CVE identifiers (e.g. CVE-2021-44228), CVSS scores, or vulnerability severity (Critical, High, Medium).
  2. Software Inventory — identify if the log indicates unpatched, vulnerable software (e.g., outdated Chrome, vulnerable Java versions).
  3. Exploitation Evidence — determine if an active exploit attempt is targeting a known vulnerable application.

For events that have NOTHING to do with vulnerabilities or CVEs, your risk_score should be low (1.0-2.0).
If a CRITICAL or HIGH severity CVE is reported on the host, elevate the risk score (7.0-9.0) depending on whether it is remotely exploitable.

Return your verdict as JSON matching the provided schema.
  - agent_name must be "vuln_agent".
  - risk_score: 1.0 (benign) to 10.0 (critical).
  - confidence: 0.0 to 1.0.
  - mitre_tactic: relevant MITRE ATT&CK ID (e.g. "T1190 - Exploit Public-Facing Application") or "None" if benign.
  - rationale: max 2 sentences.
"""

async def analyse(log_entry: dict[str, Any]) -> AgentVerdict:
    """Run vulnerability-focused analysis on a single security event."""
    
    user_payload = (
        f"EVENT_ID: {log_entry.get('event_id', 'Unknown')}\n"
        f"SOURCE_IP: {log_entry.get('source_ip', 'Unknown')}\n"
        f"USER_ACCOUNT: {log_entry.get('user_account', 'Unknown')}\n"
        f"TIMESTAMP: {log_entry.get('timestamp', 'Unknown')}\n"
        f"RAW_LOG:\n{log_entry.get('raw_log', '')}"
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
