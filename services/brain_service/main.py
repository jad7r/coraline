#!/usr/bin/env python3
"""
Coreline-Brain Service

Automated PIR generation service that listens for incident events via Redis Pub/Sub
and generates Post-Incident Review documents using Claude AI.

Flow:
  1. jira-webhook-listener validates webhook → publishes to Redis channel "coreline:incident:created"
  2. coreline-brain-service subscribes → receives incident event
  3. Checks incident status (must be Resolved/Closed)
  4. Fetches evidence from Jira and Slack
  5. Generates PIR using Claude AI (Coreline-Brain persona)
  6. Saves PIR to filesystem
  7. Publishes completion event to "coreline:pir:completed"
  8. Emits audit events to SIEM via Cloud Logging
"""

import sys
import asyncio
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI

from services.brain_service._lib_shim import initialize_secrets, SecretLoadError, _read_secret
from services.brain_service.config import get_settings
from services.brain_service.handlers.pir_subscriber import PIRSubscriber
from services.brain_service.handlers.pir_orchestrator import PIROrchestrator
from services.brain_service.routes import health, pir

import redis.asyncio as redis

logger = structlog.get_logger(__name__)

# Global reference to subscriber task
subscriber_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Handles service startup and shutdown:
    - Startup: Load secrets, initialize Redis, start Pub/Sub subscriber
    - Shutdown: Stop subscriber, close connections, emit audit event
    """
    global subscriber_task

    # === STARTUP ===
    logger.info("service.starting", msg="Coreline-Brain Service starting...")

    config = get_settings()

    # Startup runs under its own try/except: any failure here is fatal
    # (fail-fast). Shutdown deliberately lives OUTSIDE this block so that an
    # error while stopping cleanly is not mistaken for a startup failure.
    try:
        # --- Load Secrets (Fail-Fast) ---
        # Secrets are resolved from env / OS keychain by the secrets manager and
        # by the collector shims on demand; we validate presence here so the
        # service refuses to start half-configured. We do NOT copy secrets into
        # os.environ (that would widen them to the whole process).
        logger.info("service.loading_secrets", environment=config.environment)

        secrets = initialize_secrets(
            environment=config.environment,
            fail_fast=True
        )

        # Presence checks (raise SecretLoadError via fail_fast if missing).
        secrets.get_claude_api_key()
        secrets.get_slack_bot_token()

        # Jira credentials come from env / keychain too.
        jira_api_token = _read_secret('CORELINE_JIRA_API_TOKEN', 'JIRA_API_TOKEN')
        jira_email = _read_secret('CORELINE_JIRA_EMAIL', 'JIRA_EMAIL')

        if not jira_api_token or not jira_email:
            raise SecretLoadError(
                "Jira credentials required: CORELINE_JIRA_API_TOKEN and CORELINE_JIRA_EMAIL "
                "(env or 'secops-secure-enclave' keyring)."
            )

        logger.info("service.secrets_loaded", msg="Secrets and credentials loaded successfully")

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

        # --- Ensure PIR Output Directory Exists ---
        config.pir_output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "service.output_dir_ready",
            pir_output_dir=str(config.pir_output_dir),
            msg="PIR output directory ready"
        )

        # --- Initialize Components ---
        logger.info("service.initializing_components")

        app.state.redis = redis_client
        app.state.config = config

        # Initialize PIR orchestrator
        app.state.pir_orchestrator = PIROrchestrator(
            redis_client=redis_client,
            pir_output_dir=config.pir_output_dir,
            claude_model=config.claude_model,
            claude_max_tokens=config.claude_max_tokens,
            claude_temperature=config.claude_temperature,
            generate_pir_on_status=config.generate_pir_on_status,
            skip_pir_if_exists=config.skip_pir_if_exists,
            pir_completed_channel=config.pir_completed_channel,
            channel_tracking_ttl_seconds=config.channel_tracking_ttl_seconds,
            slack_message_limit=config.slack_message_limit,
            jira_server=config.jira_server
        )

        logger.info(
            "service.components_initialized",
            claude_model=config.claude_model,
            generate_on_status=config.generate_pir_on_status,
            msg="PIR orchestrator initialized"
        )

        # --- Start Redis Pub/Sub Subscriber (Background Task) ---
        logger.info(
            "service.starting_subscriber",
            channel=config.incident_channel_name
        )

        subscriber = PIRSubscriber(
            redis_client=redis_client,
            on_pir_callback=app.state.pir_orchestrator.generate_pir_for_incident,
            channel_name=config.incident_channel_name
        )

        # Start subscriber as background task
        subscriber_task = asyncio.create_task(subscriber.start())

        # --- Emit Service Started Log ---
        logger.info(
            "service.started",
            environment=config.environment,
            port=config.port,
            msg="Coreline-Brain Service started successfully"
        )

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

    # Startup succeeded — serve requests.
    yield

    # === SHUTDOWN === (outside the startup try/except: a clean-shutdown error
    # must not be reported as a startup failure).
    logger.info("service.stopping", msg="Coreline-Brain Service shutting down...")

    if subscriber_task:
        logger.info("service.stopping_subscriber")
        subscriber.stop()
        subscriber_task.cancel()
        try:
            await subscriber_task
        except asyncio.CancelledError:
            logger.info("service.subscriber_stopped", msg="Subscriber task cancelled")

    try:
        await redis_client.aclose()
    except Exception as e:  # non-fatal: we are already shutting down
        logger.warning("service.redis_close_failed", error=str(e))

    logger.info("service.stopped", msg="Coreline-Brain Service stopped cleanly")


def create_app() -> FastAPI:
    """
    Create FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    config = get_settings()

    app = FastAPI(
        title="Coreline-Brain Service",
        description="Automated Post-Incident Review generation using Claude AI",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if config.enable_swagger else None,
        redoc_url="/redoc" if config.enable_swagger else None
    )

    # Include routers
    app.include_router(health.router, tags=["health"])
    app.include_router(pir.router, tags=["pir"])

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
        "services.brain_service.main:app",
        host=config.host,
        port=config.port,
        reload=config.reload,
        log_level=config.log_level.lower(),
        workers=1  # Single worker for Pub/Sub subscriber
    )
