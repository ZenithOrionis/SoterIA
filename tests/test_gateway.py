"""
Aegis-Swarm — LLM Gateway Smoke Test
======================================
Quick integration test that fires a trivial "ping" through the gateway
and prints the result.  Validates:

  1. Settings load correctly from `.env`.
  2. The gateway constructs the LiteLLM call without crashing.
  3. On success  → a parsed JSON dict is returned.
  4. On failure  → a standardised error dict is returned (never an exception).

Usage
-----
    python -m tests.test_gateway          # from project root
    python tests/test_gateway.py          # direct execution
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Ensure the project root is on sys.path when running directly
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.config.settings import get_settings  # noqa: E402
from src.services.llm_gateway import query_swarm_llm  # noqa: E402

# ── Test schema ──────────────────────────────────────────────────────
# Minimal JSON-Schema that the model must conform to.
PING_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "description": "Should be 'ok' if the model is alive.",
        },
        "message": {
            "type": "string",
            "description": "A short greeting from the model.",
        },
    },
    "required": ["status", "message"],
    "additionalProperties": False,
}


async def run_ping_test() -> None:
    """Fire a single ping through the gateway and report the result."""

    settings = get_settings()

    print("=" * 60)
    print("  AEGIS-SWARM  •  LLM Gateway Smoke Test")
    print("=" * 60)
    print(f"  ACTIVE_MODE   : {settings.ACTIVE_MODE.value}")
    print(
        f"  TARGET_MODEL  : "
        f"{settings.CLOUD_MODEL if settings.ACTIVE_MODE.value == 'CLOUD' else settings.LOCAL_MODEL}"
    )
    print(f"  API_KEY SET   : {'Yes' if settings.GEMINI_API_KEY else 'No'}")
    print("-" * 60)

    result = await query_swarm_llm(
        system_prompt=(
            "You are a connectivity-check bot. "
            "Respond ONLY with the required JSON schema. "
            'Set status to "ok" and message to a short greeting.'
        ),
        user_payload="ping",
        response_schema=PING_SCHEMA,
    )

    # ── Evaluate ─────────────────────────────────────────────────────
    if result.get("status") == "error":
        print("\n  [FAIL]  Gateway returned an error envelope:")
        print(f"          Code    : {result.get('error_code')}")
        print(f"          Message : {result.get('message')}")
    else:
        print("\n  [PASS]  Gateway returned valid JSON:")
        print(f"          {json.dumps(result, indent=2)}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(run_ping_test())
