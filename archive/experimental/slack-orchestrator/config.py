#!/usr/bin/env python3
"""
Configuration Management for Slack Orchestrator

Uses Pydantic Settings for environment-driven configuration with validation.
All environment variables use CORELINE_ prefix for consistency.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Literal
import json


class Settings(BaseSettings):
    """Service configuration loaded from environment variables."""

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
    response_team_user_ids: list[str] = Field(
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
    @validator('enable_swagger')
    def validate_swagger_not_in_prod(cls, v, values):
        """Ensure Swagger UI is disabled in production."""
        if v and values.get('environment') == 'prod':
            raise ValueError("Swagger UI must be disabled in production (CORELINE_ENABLE_SWAGGER=false)")
        return v

    @validator('response_team_user_ids', pre=True)
    def parse_response_team_user_ids(cls, v):
        """Parse response team user IDs from JSON string or list."""
        if isinstance(v, str):
            # Handle empty string
            if not v or v.strip() == '':
                return []

            # Parse JSON array
            try:
                parsed = json.loads(v)
                if not isinstance(parsed, list):
                    raise ValueError("response_team_user_ids must be a JSON array")
                return parsed
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON for response_team_user_ids: {e}")

        return v

    # === Configuration ===
    class Config:
        """Pydantic Settings configuration."""

        env_prefix = "CORELINE_"
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"


def get_settings() -> Settings:
    """
    Get application settings.

    Returns:
        Settings instance with values from environment variables

    Raises:
        ValidationError: If configuration is invalid
    """
    return Settings()
