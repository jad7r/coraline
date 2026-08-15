#!/usr/bin/env python3
"""
Configuration Management for Slack Orchestrator

Uses Pydantic Settings for environment-driven configuration with validation.
All environment variables use CORELINE_ prefix for consistency.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Annotated, Literal
import json


class Settings(BaseSettings):
    """Service configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="CORELINE_",
        case_sensitive=False,
        # Absolute path so the service's .env loads regardless of the process's
        # current working directory (the app is launched from the repo root).
        env_file=str(Path(__file__).resolve().parent / ".env"),
        env_file_encoding="utf-8",
    )

    # === Core Settings ===
    environment: Literal["dev", "staging", "prod"] = Field(
        default="prod",
        description="Deployment environment"
    )

    service_name: str = Field(
        default="slack-orchestrator",
        description="Service identifier for logging and audit"
    )

    # === Server Settings ===
    port: int = Field(
        default=8081,
        ge=1024,
        le=65535,
        description="HTTP server port"
    )

    host: str = Field(
        default="0.0.0.0",
        description="HTTP server host"
    )

    # === Redis Settings ===
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for Pub/Sub"
    )

    redis_timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Redis connection timeout in seconds"
    )

    incident_channel_name: str = Field(
        default="coreline:incident:created",
        description="Redis Pub/Sub channel for incident notifications"
    )

    # === Slack Settings ===
    # `NoDecode` stops pydantic-settings from JSON-decoding the env value before
    # our validator runs, so an empty or CSV value is handled gracefully instead
    # of crashing get_settings() with a SettingsError.
    response_team_user_ids: Annotated[list[str], NoDecode] = Field(
        default=[],
        description="Slack user IDs to invite to incident channels (e.g., ['U01234567', 'U89ABCDEF'])"
    )

    # === Channel Tracking ===
    channel_tracking_ttl_seconds: int = Field(
        default=7776000,  # 90 days
        ge=86400,  # At least 1 day
        description="TTL for channel tracking in Redis (seconds)"
    )

    # === Logging Settings ===
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level"
    )

    log_json: bool = Field(
        default=True,
        description="Use JSON-formatted logging for Cloud Logging"
    )

    # === Development Settings ===
    enable_swagger: bool = Field(
        default=False,
        description="Enable Swagger UI and ReDoc (disable in production)"
    )

    reload: bool = Field(
        default=False,
        description="Enable auto-reload for development"
    )

    # === Validators ===
    @field_validator('enable_swagger')
    @classmethod
    def validate_swagger_not_in_prod(cls, v, info):
        """Ensure Swagger UI is disabled in production."""
        if v and info.data.get('environment') == 'prod':
            raise ValueError("Swagger UI must be disabled in production (CORELINE_ENABLE_SWAGGER=false)")
        return v

    @field_validator('response_team_user_ids', mode='before')
    @classmethod
    def parse_response_team_user_ids(cls, v):
        """Parse response team user IDs from a JSON array, a CSV string, or a list.

        Accepts (env values arrive as raw strings thanks to ``NoDecode``):
          - ``[]`` / unset / empty / whitespace  -> []
          - ``'["U1", "U2"]'`` (JSON array)       -> ["U1", "U2"]
          - ``'U1,U2'`` (comma-separated)          -> ["U1", "U2"]
          - an actual list (defaults, tests)       -> unchanged
        """
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            # JSON array form.
            if stripped.startswith('['):
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON for response_team_user_ids: {e}")
                if not isinstance(parsed, list):
                    raise ValueError("response_team_user_ids must be a JSON array")
                return parsed
            # Comma-separated fallback.
            return [item.strip() for item in stripped.split(',') if item.strip()]
        raise ValueError("response_team_user_ids must be a list, JSON array, or CSV string")


def get_settings() -> Settings:
    """
    Get application settings.

    Returns:
        Settings instance with values from environment variables

    Raises:
        ValidationError: If configuration is invalid
    """
    return Settings()
