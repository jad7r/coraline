#!/usr/bin/env python3
"""
Configuration Management for Coreline-Brain Service

Uses Pydantic Settings for environment-driven configuration with validation.
All environment variables use CORELINE_ prefix for consistency.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Literal
from pathlib import Path


class Settings(BaseSettings):
    """Service configuration loaded from environment variables."""

    # === Core Settings ===
    environment: Literal["dev", "staging", "prod"] = Field(
        default="prod",
        description="Deployment environment"
    )

    service_name: str = Field(
        default="coreline-brain-service",
        description="Service identifier for logging and audit"
    )

    # === Server Settings ===
    port: int = Field(
        default=8082,
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

    pir_completed_channel: str = Field(
        default="coreline:pir:completed",
        description="Redis Pub/Sub channel for PIR completion events"
    )

    # === Channel Tracking ===
    channel_tracking_ttl_seconds: int = Field(
        default=7776000,  # 90 days
        ge=86400,  # At least 1 day
        description="TTL for channel tracking in Redis (seconds)"
    )

    # === Anthropic Settings ===
    claude_model: str = Field(
        default="claude-sonnet-4-5",
        description="Claude model for PIR generation"
    )

    claude_max_tokens: int = Field(
        default=16000,
        ge=1000,
        le=200000,
        description="Maximum tokens for Claude response"
    )

    claude_temperature: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Temperature for Claude generation (lower = more deterministic)"
    )

    # === Jira Settings ===
    jira_server: str = Field(
        default="https://pantheon.atlassian.net",
        description="Jira server URL"
    )

    # === PIR Output Settings ===
    pir_output_dir: Path = Field(
        default=Path("/output/pirs"),
        description="Directory for generated PIR files"
    )

    # === Message Limits ===
    slack_message_limit: int = Field(
        default=1000,
        ge=100,
        le=5000,
        description="Maximum Slack messages to fetch per incident"
    )

    # === PIR Generation Settings ===
    generate_pir_on_status: list[str] = Field(
        default=["Resolved", "Closed"],
        description="Jira status values that trigger PIR generation"
    )

    skip_pir_if_exists: bool = Field(
        default=True,
        description="Skip PIR generation if file already exists"
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

    @validator('pir_output_dir')
    def validate_pir_output_dir(cls, v):
        """Ensure PIR output directory is absolute path."""
        if not v.is_absolute():
            raise ValueError("PIR output directory must be an absolute path")
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
