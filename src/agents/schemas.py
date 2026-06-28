"""
SoterIA — Agent Output Schemas
====================================
**Architectural Law 4 enforcement point.**

Every agent in the swarm MUST return an ``AgentVerdict`` Pydantic model.
This guarantees:
  * Strict type validation at the boundary between LLM output and Python.
  * A deterministic, machine-readable structure the Tribunal can aggregate.
  * A JSON-Schema that can be forwarded to ``query_swarm_llm`` so the model
    is constrained to this exact shape.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AgentVerdict(BaseModel):
    """Structured verdict returned by every swarm agent.

    Attributes
    ----------
    agent_name : str
        Identifier of the agent that produced this verdict
        (e.g. ``"identity_agent"``).
    risk_score : float
        Threat severity on a 1.0 – 10.0 scale.
        1.0 = completely benign, 10.0 = critical active attack.
    confidence : float
        Self-assessed confidence in the verdict, 0.0 – 1.0.
    mitre_tactic : str
        MITRE ATT&CK tactic ID and name, or ``"None"`` if benign.
    rationale : str
        Two-sentence maximum justification for the score.
    """

    agent_name: str = Field(
        ...,
        description="Identifier of the agent (e.g. 'identity_agent').",
    )
    risk_score: float = Field(
        ...,
        ge=1.0,
        le=10.0,
        description="Threat severity: 1.0 (benign) to 10.0 (critical).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Self-assessed confidence: 0.0 (guess) to 1.0 (certain).",
    )
    mitre_tactic: str = Field(
        ...,
        description="MITRE ATT&CK tactic ID + name, or 'None' if benign.",
    )
    rationale: str = Field(
        ...,
        max_length=1000,
        description="Max 2-sentence justification for the score.",
    )


# ── JSON-Schema export for LiteLLM structured output ────────────────

AGENT_VERDICT_SCHEMA: dict = AgentVerdict.model_json_schema()
