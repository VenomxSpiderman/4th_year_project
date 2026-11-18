"""
config.py
─────────
Centralised environment-variable configuration for the BPMN Security pipeline.

Raises ConfigurationError (a subclass of RuntimeError) on first access if any
required variable is missing.  All other modules import from here instead of
calling os.environ directly.
"""
from __future__ import annotations

import os
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when a required environment variable is missing or invalid."""


def get_neo4j_uri() -> str:
    return os.environ.get("NEO4J_URI", "bolt://localhost:7687")


def get_neo4j_user() -> str:
    return os.environ.get("NEO4J_USER", "neo4j")


def get_neo4j_password() -> str:
    pw = os.environ.get("NEO4J_PASSWORD", "")
    if not pw:
        raise ConfigurationError(
            "NEO4J_PASSWORD environment variable is not set.\n"
            "Set it before running:\n"
            "    export NEO4J_PASSWORD=<your-password>"
        )
    return pw


def get_catalogue_db_path() -> Path:
    env_val = os.environ.get("ENISA_CATALOGUE_DB")
    return Path(env_val) if env_val else Path("data") / "enisa_catalogue.db"
