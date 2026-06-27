"""
SoterIA — Universal LLM Gateway
=====================================
**Architectural Law 2 enforcement point.**

This module is the ONE AND ONLY interface to any Large Language Model.
No other file in the project may import `google.generativeai`, `openai`,
or `ollama` directly.  Every LLM call in the system flows through
`query_swarm_llm`.

The function:
  1. Reads the active mode from Settings (CLOUD / LOCAL).
  2. Builds the correct LiteLLM payload (model string, API key / base URL).
  3. Forces structured JSON output via `response_format`.
  4. Catches network / timeout / provider errors and returns a
     standardised error dict — the server never crashes due to an LLM hiccup.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import litellm

from src.config.settings import ActiveMode, get_settings

# ── Module-level config ──────────────────────────────────────────────
logger = logging.getLogger("soteria.llm_gateway")

# Suppress litellm's noisy default logging
litellm.suppress_debug_info = True

# ── Standardised error envelope ──────────────────────────────────────

_ERROR_TEMPLATE: dict[str, Any] = {
    "status": "error",
    "source": "llm_gateway",
    "data": None,
}


def _make_error(message: str, *, code: str = "LLM_ERROR") -> dict[str, Any]:
    """Return a deterministic error dict that callers can pattern-match on."""
    return {**_ERROR_TEMPLATE, "error_code": code, "message": message}


# ── Public gateway function ──────────────────────────────────────────


async def query_swarm_llm(
    system_prompt: str,
    user_payload: str,
    response_schema: dict[str, Any],
) -> dict[str, Any]:
    """Send a structured prompt to the active LLM and return parsed JSON.

    Parameters
    ----------
    system_prompt:
        The system-level instruction that shapes the model's behaviour.
    user_payload:
        The user-level content (e.g. a raw log line, an alert blob).
    response_schema:
        A JSON-Schema dict describing the expected response structure.
        Passed to LiteLLM's ``response_format`` so the model is
        constrained to return valid JSON matching this schema.

    Returns
    -------
    dict
        On success: the parsed JSON object from the model.
        On failure: a standardised error dict with keys
        ``status``, ``error_code``, ``message``, ``source``, ``data``.
    """

    settings = get_settings()

    # ── Build provider-specific kwargs ───────────────────────────────
    completion_kwargs: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ],
        "temperature": 0.0,  # deterministic extraction
    }

    # Force LOCAL mode to override stubborn OS environment variables
    FORCED_MODE = ActiveMode.LOCAL

    if FORCED_MODE == ActiveMode.CLOUD:
        completion_kwargs["model"] = settings.CLOUD_MODEL
        completion_kwargs["api_key"] = settings.GEMINI_API_KEY
        completion_kwargs["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "soteria_response",
                "strict": True,
                "schema": response_schema,
            },
        }

        if not settings.GEMINI_API_KEY:
            return _make_error(
                "GEMINI_API_KEY is not set. Cannot route to CLOUD mode.",
                code="CONFIG_ERROR",
            )

    elif FORCED_MODE == ActiveMode.LOCAL:
        completion_kwargs["model"] = settings.LOCAL_MODEL
        completion_kwargs["api_base"] = settings.LOCAL_API_BASE
        
        # Local Ollama fallback: use basic json_object format and inject a simple structure example
        completion_kwargs["response_format"] = {"type": "json_object"}
        
        example_json = "{\n"
        for key in response_schema.get("properties", {}).keys():
            example_json += f'  "{key}": "...",\n'
        example_json += "}"

        completion_kwargs["messages"][0]["content"] += (
            f"\n\nYou MUST return valid JSON. Do not include any markdown formatting, only the raw JSON object.\n"
            f"Your response must be a single flat JSON object containing exactly these keys:\n"
            f"{example_json}"
        )

    else:
        return _make_error(
            f"Unknown ACTIVE_MODE: {settings.ACTIVE_MODE!r}",
            code="CONFIG_ERROR",
        )

    # ── Call LiteLLM ─────────────────────────────────────────────────
    try:
        response = await litellm.acompletion(**completion_kwargs)

        raw_content: str = response.choices[0].message.content  # type: ignore[union-attr]

        # Llama 3.1 occasionally wraps JSON in markdown blocks despite instructions
        raw_content = raw_content.strip()
        if raw_content.startswith("```"):
            lines = raw_content.splitlines()
            if len(lines) > 2 and lines[0].startswith("```"):
                lines = lines[1:-1]
                if len(lines) > 0 and lines[-1].startswith("```"):
                    lines = lines[:-1]
            raw_content = "\n".join(lines).strip()

        # Parse the model's JSON string into a Python dict
        parsed: dict[str, Any] = json.loads(raw_content)
        
        # Unwrap if the LLM hallucinated the JSON schema definition
        if "properties" in parsed and "type" in parsed and parsed["type"] == "object":
            # Sometimes models return the actual answer values inside the schema's 'properties' block
            is_schema_wrapper = True
            for key in response_schema.get("required", []):
                if key not in parsed["properties"]:
                    is_schema_wrapper = False
            if is_schema_wrapper:
                parsed = parsed["properties"]
                
        return parsed

    except json.JSONDecodeError as exc:
        logger.error("LLM returned non-JSON content: %s", exc)
        return _make_error(
            f"Model response was not valid JSON: {exc}",
            code="PARSE_ERROR",
        )

    except litellm.exceptions.Timeout as exc:
        logger.error("LLM request timed out: %s", exc)
        return _make_error(
            f"LLM request timed out: {exc}",
            code="TIMEOUT",
        )

    except litellm.exceptions.APIConnectionError as exc:
        logger.error("Could not connect to LLM provider: %s", exc)
        return _make_error(
            f"Connection to LLM provider failed: {exc}",
            code="CONNECTION_ERROR",
        )

    except litellm.exceptions.AuthenticationError as exc:
        logger.error("LLM authentication failed: %s", exc)
        return _make_error(
            f"Authentication failed — check your API key: {exc}",
            code="AUTH_ERROR",
        )

    except litellm.exceptions.RateLimitError as exc:
        logger.warning("LLM rate-limited: %s", exc)
        return _make_error(
            f"Rate limited by LLM provider: {exc}",
            code="RATE_LIMIT",
        )

    except litellm.exceptions.ServiceUnavailableError as exc:
        logger.warning("LLM service unavailable (503): %s", exc)
        return _make_error(
            f"LLM provider temporarily unavailable: {exc}",
            code="SERVICE_UNAVAILABLE",
        )

    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        logger.exception("Unexpected LLM gateway error")
        return _make_error(
            f"Unexpected error in LLM gateway: {type(exc).__name__}: {exc}",
            code="UNKNOWN_ERROR",
        )

