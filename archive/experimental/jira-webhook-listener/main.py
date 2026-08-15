#!/usr/bin/env python3
"""
Coreline Jira Webhook Listener Service

FastAPI application for receiving and validating Jira webhooks.

Implements security guardrails:
- G2.1: HMAC signature verification
- G2.2: Replay attack prevention
- G2.3: Schema validation

Dependencies:
- Redis: Replay prevention (webhook ID tracking)
- Google Secret Manager: Webhook secret storage
- Cloud Logging: Audit event emission to SIEM
"""

import sys
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis

# Add parent directory to path for imports
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.shared import initialize_secrets, SecretLoadError
from config import get_settings
from security.hmac_verifier import HMACVerifier
from security.replay_prevention import ReplayProtection
from handlers.audit_logger import AuditLogger
from handlers.webhook_handler import WebhookHandler
from routes import webhooks, health

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Handles service startup and shutdown:
    - Startup: Initialize secrets, Redis, components
    - Shutdown: Close connections gracefully
    """
    # === STARTUP ===
    logger.info("service.starting", msg="Coreline Jira Webhook Listener starting...")

    # Load configuration
    config = get_settings()

    logger.info(
        "service.config_loaded",
        environment=config.environment,
        redis_url=config.redis_url,
        max_webhook_age=config.max_webhook_age_seconds,
        msg="Configuration loaded"
    )

    try:
        # Initialize secrets (fail-fast if missing)
        logger.info("service.loading_secrets", msg="Loading secrets from Secret Manager...")

        secrets = initialize_secrets(
            environment=config.environment,
            fail_fast=True
        )

        webhook_secret = secrets.get_jira_webhook_secret()

        logger.info(
            "service.secrets_loaded",
            secret_length=len(webhook_secret),
            msg="Webhook secret loaded successfully"
        )

        # Store in app state
        app.state.webhook_secret = webhook_secret
        app.state.config = config

    except SecretLoadError as e:
        logger.critical(
            "service.secret_load_failed",
            error=str(e),
            msg="Cannot start service without webhook secret"
        )
        sys.exit(1)

    try:
        # Initialize Redis client
        logger.info(
            "service.connecting_redis",
            redis_url=config.redis_url,
            msg="Connecting to Redis..."
        )

        redis_client = redis.from_url(
            config.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=config.redis_timeout
        )

        # Verify connectivity
        await redis_client.ping()

        logger.info("service.redis_connected", msg="Redis connection established")

        # Store in app state
        app.state.redis = redis_client

    except redis.RedisError as e:
        logger.critical(
            "service.redis_connection_failed",
            error=str(e),
            error_type=type(e).__name__,
            msg="Cannot start service without Redis"
        )
        sys.exit(1)

    # Initialize components
    logger.info("service.initializing_components", msg="Initializing security components...")

    app.state.hmac_verifier = HMACVerifier(secret=webhook_secret)
    app.state.replay_protection = ReplayProtection(redis_client=redis_client)
    app.state.audit_logger = AuditLogger(
        service_name=config.service_name,
        environment=config.environment
    )

    # Initialize webhook handler
    app.state.webhook_handler = WebhookHandler(
        hmac_verifier=app.state.hmac_verifier,
        replay_protection=app.state.replay_protection,
        audit_logger=app.state.audit_logger,
        max_webhook_age_seconds=config.max_webhook_age_seconds,
        redis_client=redis_client,
        incident_channel_name=config.incident_channel_name
    )

    logger.info("service.components_initialized", msg="All components initialized successfully")

    # Emit service started audit event
    app.state.audit_logger.log_service_started()

    logger.info(
        "service.started",
        environment=config.environment,
        port=config.port,
        msg="Coreline Jira Webhook Listener started successfully"
    )

    yield

    # === SHUTDOWN ===
    logger.info("service.stopping", msg="Coreline Jira Webhook Listener shutting down...")

    # Emit service stopped audit event
    if hasattr(app.state, 'audit_logger'):
        app.state.audit_logger.log_service_stopped()

    # Close Redis connection
    if hasattr(app.state, 'redis'):
        await app.state.redis.close()
        logger.info("service.redis_closed", msg="Redis connection closed")

    logger.info("service.stopped", msg="Coreline Jira Webhook Listener stopped")


# Create FastAPI application
def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.

    Returns:
        Configured FastAPI app
    """
    config = get_settings()

    app = FastAPI(
        title="Coreline Jira Webhook Listener",
        description="Receives and validates Jira security incident webhooks with HMAC authentication, replay prevention, and schema validation",
        version="1.0.0",
        lifespan=lifespan,
        # Disable docs in production
        docs_url="/docs" if config.enable_swagger else None,
        redoc_url="/redoc" if config.enable_swagger else None
    )

    # CORS middleware (restrictive in production)
    if config.environment == "dev":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Include routers
    app.include_router(webhooks.router)
    app.include_router(health.router)

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_settings()

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.reload,
        log_level=config.log_level.lower()
    )
