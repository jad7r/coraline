#!/usr/bin/env python3
"""
Configuration Management for Jira Webhook Listener

Loads configuration from environment variables with sensible defaults.
Uses Pydantic Settings for validation and type safety.

Environment Variables:
    CORELINE_ENVIRONMENT: Deployment environment (dev, staging, prod)
    CORELINE_REDIS_URL: Redis connection URL
    CORELINE_MAX_WEBHOOK_AGE_SECONDS: Maximum webhook age for replay prevention
    CORELINE_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    CORELINE_PORT: HTTP server port (default: 8080)
"""

from pydantic import Field, validator
from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    """Service configuration loaded from environment variables."""

    # === Core Settings ===
    environment: Literal["dev", "staging", "prod"] = Field(
        default="prod",
        description="Deployment environment"
    )

    service_name: str = Field(
        default="jira-webhook-listener",
        description="Service name for logging and metrics"
    )

    # === Server Settings ===
    port: int = Field(
        default=8080,
        description="HTTP server port",
        ge=1024,
        le=65535
    )

    host: str = Field(
        default="0.0.0.0",
        description="HTTP server host"
    )

    # === Redis Settings ===
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for replay prevention"
    )

    redis_timeout: int = Field(
        default=5,
        description="Redis connection timeout in seconds",
        ge=1,
        le=30
    )

    incident_channel_name: str = Field(
        default="coreline:incident:created",
        description="Redis Pub/Sub channel for publishing incident events to Slack orchestrator"
    )

    # === Security Settings ===
    max_webhook_age_seconds: int = Field(
        default=300,
        description="Maximum webhook age in seconds (replay prevention)",
        ge=60,  # Min 1 minute
        le=3600  # Max 1 hour
    )

    webhook_id_ttl_seconds: int = Field(
        default=86400,
        description="TTL for webhook IDs in Redis (24 hours default)",
        ge=3600,  # Min 1 hour
        le=604800  # Max 7 days
    )

    # === Logging Settings ===
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level"
    )

    log_json: bool = Field(
        default=True,
        description="Use JSON logging format (for Cloud Logging)"
    )

    # === Performance Settings ===
    max_request_body_size: int = Field(
        default=1048576,  # 1 MB
        description="Maximum request body size in bytes",
        ge=10240,  # Min 10 KB
        le=10485760  # Max 10 MB
    )

    request_timeout: int = Field(
        default=30,
        description="Request timeout in seconds",
        ge=5,
        le=120
    )

    # === Development/Testing Settings ===
    enable_swagger: bool = Field(
        default=False,
        description="Enable Swagger UI (disable in production)"
    )

    reload: bool = Field(
        default=False,
        description="Enable auto-reload on code changes (dev only)"
    )

    @validator('enable_swagger')
    def validate_swagger_not_in_prod(cls, v, values):
        """Ensure Swagger UI is disabled in production."""
        if v and values.get('environment') == 'prod':
            raise ValueError("Swagger UI must be disabled in production environment")
        return v

    @validator('reload')
    def validate_reload_not_in_prod(cls, v, values):
        """Ensure auto-reload is disabled in production."""
        if v and values.get('environment') == 'prod':
            raise ValueError("Auto-reload must be disabled in production environment")
        return v

    class Config:
        """Pydantic settings configuration."""
        # Environment variable prefix
        env_prefix = "CORELINE_"

        # Case sensitivity
        case_sensitive = False

        # Load from .env file if present (for local development)
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """
    Get settings instance (singleton pattern).

    Returns:
        Settings instance loaded from environment
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings():
    """Reset settings (useful for testing)."""
    global _settings
    _settings = None
