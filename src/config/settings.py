"""
SoterIA — Centralised Application Settings
================================================
Uses Pydantic v2 BaseSettings to load environment variables from `.env`.
This is the SINGLE SOURCE OF TRUTH for all runtime configuration.
No other module should read os.environ directly for these values.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class ActiveMode(str, Enum):
    """The two supported execution modes for the LLM gateway."""
    CLOUD = "CLOUD"
    LOCAL = "LOCAL"


class Settings(BaseSettings):
    """
    Immutable application configuration loaded once at startup.

    Values are resolved in this priority order:
      1. Explicit environment variables
      2. `.env` file in the project root
      3. Defaults defined below
    """

    # ── Operational Mode ─────────────────────────────────────────────
    ACTIVE_MODE: ActiveMode = Field(
        default=ActiveMode.LOCAL,
        description="CLOUD routes to Gemini via API key; LOCAL routes to a self-hosted Ollama instance.",
    )

    # ── Cloud Provider (Gemini) ──────────────────────────────────────
    GEMINI_API_KEY: str = Field(
        default="",
        description="API key for Google Gemini. Required when ACTIVE_MODE=CLOUD.",
    )
    CLOUD_MODEL: str = Field(
        default="gemini/gemini-2.5-flash",
        description="LiteLLM model identifier for the cloud provider.",
    )

    # ── Local Provider (Ollama) ──────────────────────────────────────
    LOCAL_MODEL: str = Field(
        default="ollama/llama3.2",
        description="LiteLLM model identifier for the local Ollama instance.",
    )
    LOCAL_API_BASE: str = Field(
        default="http://localhost:11434",
        description="Base URL of the local Ollama server.",
    )

    # ── Pydantic-Settings wiring ─────────────────────────────────────
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, singleton Settings instance."""
    return Settings()
