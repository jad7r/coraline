#!/usr/bin/env python3
"""
Coreline Slack Orchestrator Service

Receives incident notifications via Redis Pub/Sub and creates Slack incident channels.

Flow:
  1. jira-webhook-listener validates webhook → publishes to Redis channel "coreline:incident:created"
  2. slack-orchestrator subscribes → receives incident event
  3. Creates private Slack channel with naming convention (sec-ops-inc-{year}-{number})
  4. Invites response team
  5. Posts initial incident summary
  6. Emits audit events to SIEM via Cloud Logging
"""

import sys
import asyncio
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI

from services.shared import initialize_secrets, SecretLoadError
from services.slack_orchestrator.config import get_settings
from services.slack_orchestrator.handlers.audit_logger import AuditLogger
from services.slack_orchestrator.handlers.incident_subscriber import IncidentSubscriber
from services.slack_orchestrator.handlers.slack_channel_creator import SlackChannelCreator
from services.slack_orchestrator.utils.duplicate_tracker import DuplicateTracker
from services.slack_orchestrator.routes import health

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import redis.asyncio as redis

logger = structlog.get_logger(__name__)

# Global reference to subscriber task
subscriber_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Handles service startup and shutdown:
    - Startup: Load secrets, initialize Redis/Slack, start Pub/Sub subscriber
    - Shutdown: Stop subscriber, close connections, emit audit event
    """
    global subscriber_task

    # === STARTUP ===
    logger.info("service.starting", msg="Coreline Slack Orchestrator starting...")

    config = get_settings()

    try:
        # --- Load Secrets (Fail-Fast) ---
        logger.info("service.loading_secrets", environment=config.environment)

        secrets = initialize_secrets(
            environment=config.environment,
            fail_fast=True
        )

        slack_token = secrets.get_slack_bot_token()

        logger.info("service.secrets_loaded", msg="Secrets loaded successfully")

        # --- Initialize Redis ---
        logger.info("service.initializing_redis", redis_url=config.redis_url)

        redis_client = redis.from_url(
            config.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=config.redis_timeout
        )

        # Verify Redis connectivity
        await redis_client.ping()
        logger.info("service.redis_connected", msg="Redis connected successfully")

        # --- Initialize Slack Client ---
        logger.info("service.initializing_slack")

        slack_client = WebClient(token=slack_token)

        # Test Slack authentication
        try:
            auth_response = slack_client.auth_test()
            logger.info(
                "service.slack_connected",
                bot_user_id=auth_response['user_id'],
                team_id=auth_response['team_id'],
                team_name=auth_response.get('team'),
                msg="Slack client authenticated successfully"
            )
        except SlackApiError as e:
            logger.critical(
                "service.slack_auth_failed",
                error=str(e),
                error_code=e.response.get('error'),
                msg="Failed to authenticate with Slack"
            )
            sys.exit(1)

        # --- Initialize Components ---
        logger.info("service.initializing_components")

        app.state.redis = redis_client
        app.state.slack = slack_client
        app.state.config = config

        app.state.audit_logger = AuditLogger(
            service_name=config.service_name,
            environment=config.environment
        )

        app.state.duplicate_tracker = DuplicateTracker(
            redis_client=redis_client,
            ttl_seconds=config.channel_tracking_ttl_seconds
        )

        app.state.channel_creator = SlackChannelCreator(
            slack_client=slack_client,
            duplicate_tracker=app.state.duplicate_tracker,
            audit_logger=app.state.audit_logger,
            response_team_user_ids=config.response_team_user_ids
        )

        logger.info(
            "service.components_initialized",
            response_team_size=len(config.response_team_user_ids),
            msg="Core components initialized"
        )

        # --- Start Redis Pub/Sub Subscriber (Background Task) ---
        logger.info(
            "service.starting_subscriber",
            channel=config.incident_channel_name
        )

        subscriber = IncidentSubscriber(
            redis_client=redis_client,
            on_incident_callback=app.state.channel_creator.create_incident_channel,
            channel_name=config.incident_channel_name
        )

        # Start subscriber as background task
        subscriber_task = asyncio.create_task(subscriber.start())

        # --- Emit Service Started Audit Event ---
        app.state.audit_logger.log_service_started()

        logger.info(
            "service.started",
            environment=config.environment,
            port=config.port,
            msg="Coreline Slack Orchestrator started successfully"
        )

        yield

        # === SHUTDOWN ===
        logger.info("service.stopping", msg="Coreline Slack Orchestrator shutting down...")

        # Stop subscriber
        if subscriber_task:
            logger.info("service.stopping_subscriber")
            subscriber.stop()
            subscriber_task.cancel()

            try:
                await subscriber_task
            except asyncio.CancelledError:
                logger.info("service.subscriber_stopped", msg="Subscriber task cancelled")

        # Emit Service Stopped audit event
        app.state.audit_logger.log_service_stopped()

        # Close Redis connection
        await redis_client.close()

        logger.info("service.stopped", msg="Coreline Slack Orchestrator stopped cleanly")

    except SecretLoadError as e:
        logger.critical(
            "service.secret_load_failed",
            error=str(e),
            msg="Cannot start service without required secrets"
        )
        sys.exit(1)

    except redis.RedisError as e:
        logger.critical(
            "service.redis_connection_failed",
            error=str(e),
            msg="Cannot start service without Redis connectivity"
        )
        sys.exit(1)

    except Exception as e:
        logger.critical(
            "service.startup_failed",
            error=str(e),
            error_type=type(e).__name__,
            msg="Unexpected error during service startup"
        )
        sys.exit(1)


def create_app() -> FastAPI:
    """
    Create FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    config = get_settings()

    app = FastAPI(
        title="Coreline Slack Orchestrator",
        description="Creates Slack incident response channels from Jira webhook notifications",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if config.enable_swagger else None,
        redoc_url="/redoc" if config.enable_swagger else None
    )

    # Include routers
    app.include_router(health.router, tags=["health"])

    return app


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_settings()

    # Configure structlog for JSON logging
    if config.log_json:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

    # Run server
    uvicorn.run(
        "services.slack_orchestrator.main:app",
        host=config.host,
        port=config.port,
        reload=config.reload,
        log_level=config.log_level.lower(),
        workers=1  # Single worker for Pub/Sub subscriber
    )
