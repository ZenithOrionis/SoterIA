"""
SoterIA — Identity Agent
==============================
Analyses security events through the lens of **user identity and
authentication behaviour**.

Focus areas (and ONLY these):
  * User account names — is it an admin / service account?
  * Event 4625 — failed logon attempts (brute-force indicators).
  * Login frequency anomalies implied by the raw log.

This agent does NOT look at network addresses, process execution, or
file-system artefacts.  Those are the responsibility of sibling agents.
"""

from __future__ import annotations

import logging

from src.agents.schemas import AgentVerdict, AGENT_VERDICT_SCHEMA
from src.services.llm_gateway import query_swarm_llm
from src.db.neo4j_client import neo4j_client

logger = logging.getLogger("soteria.agent.identity")

_AGENT_NAME = "identity_agent"

_SYSTEM_PROMPT = """\
You are the Identity Analysis Agent in the SoterIA SOC.

YOUR MANDATE — analyse the security log below and evaluate ONLY:
  1. The user account involved — is it a privileged account (Administrator,
     admin, domain_admin, svc_*)?  Privileged accounts under attack are
     higher risk.
  2. Windows Event ID 4625 (Failed Logon) — multiple failed logons against
     the same account indicate brute-force.  A single 4625 from an external
     IP against an admin account is still noteworthy.
  3. Logon type and authentication context in the raw log body.

IGNORE network addresses, process names, service installations, and file
paths.  Other agents handle those.

Return your verdict as JSON matching the provided schema.
  - agent_name must be "identity_agent".
  - risk_score: 1.0 (benign) to 10.0 (critical).
  - confidence: 0.0 to 1.0.
  - mitre_tactic: relevant MITRE ATT&CK ID (e.g. "T1110 - Brute Force")
    or "None" if benign.
  - rationale: max 2 sentences.
"""


async def analyse(log_entry: dict) -> AgentVerdict:
    """Run identity-focused analysis on a single security event.

    Parameters
    ----------
    log_entry : dict
        A ``security_events`` row dict (must contain ``raw_log``,
        ``user_account``, ``event_id``).

    Returns
    -------
    AgentVerdict
        Validated Pydantic model.  On LLM failure a safe low-risk
        default is returned so the Tribunal can still aggregate.
    """

    user_account = log_entry['user_account']
    blast_radius_context = ""
    
    if user_account and user_account != "Unknown":
        br = neo4j_client.check_blast_radius(user_account)
        if br:
            blast_radius_context = (
                f"\n\n[CRITICAL BLAST RADIUS WARNING]\n"
                f"Neo4j Graph Analysis confirms user '{user_account}' has a path to "
                f"Domain Admins via '{br['target']}' in {br['hops']} hops!\n"
                f"This identity is a high-value vector. Elevate risk score heavily if compromised."
            )

    user_payload = (
        f"EVENT_ID: {log_entry['event_id']}\n"
        f"USER_ACCOUNT: {user_account}\n"
        f"TIMESTAMP: {log_entry['timestamp']}\n"
        f"RAW_LOG:\n{log_entry['raw_log']}"
        f"{blast_radius_context}"
    )

    result = await query_swarm_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_payload=user_payload,
        response_schema=AGENT_VERDICT_SCHEMA,
    )

    # ── Gateway returned an error envelope ───────────────────────────
    if result.get("status") == "error":
        logger.warning("LLM error in %s: %s", _AGENT_NAME, result.get("message"))
        return AgentVerdict(
            agent_name=_AGENT_NAME,
            risk_score=1.0,
            confidence=0.0,
            mitre_tactic="None",
            rationale=f"LLM unavailable — defaulting to low risk. Error: {result.get('error_code')}",
        )

    # ── Parse and validate through Pydantic ──────────────────────────
    try:
        # Force the correct agent name regardless of what the model returns
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
