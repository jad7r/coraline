#!/usr/bin/env python3
"""
Health Check Endpoints

Provides liveness and readiness probes for Kubernetes/Cloud Run orchestration.
"""

from fastapi import APIRouter, Request, HTTPException
import redis.asyncio as redis
import structlog
from services.shared.secrets import initialize_secrets

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Liveness probe endpoint.

    Returns HTTP 200 if service is running (not crashed).
    Does not check external dependencies.

    Returns:
        dict: Health status
    """
    return {
        "status": "healthy",
        "service": "coreline-brain-service"
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """
    Readiness probe endpoint.

    Returns HTTP 200 if service is ready to handle requests.
    Checks:
    - Redis connectivity
    - Required credentials are loaded

    Args:
        request: FastAPI request object (provides access to app.state)

    Returns:
        dict: Readiness status

    Raises:
        HTTPException: 503 if service is not ready
    """
    checks = {
        "redis": False,
        "credentials": False
    }

    # Check Redis
    try:
        await request.app.state.redis.ping()
        checks["redis"] = True
    except (redis.RedisError, AttributeError) as e:
        logger.warning(
            "health.redis_check_failed",
            error=str(e),
            msg="Redis health check failed"
        )

    # Check required credentials are present (not making actual API calls)
    try:
        secrets = initialize_secrets(fail_fast=False)
        credentials_loaded = all((
            secrets.get_claude_api_key(),
            secrets.get_jira_api_token(),
            secrets.get_jira_email(),
            secrets.get_slack_bot_token(),
        ))

        if credentials_loaded:
            checks["credentials"] = True
        else:
            logger.warning(
                "health.credentials_check_failed",
                msg="Required credentials not found in environment or keychain"
            )
    except Exception as e:
        logger.warning(
            "health.credentials_check_error",
            error=str(e),
            msg="Error checking credentials"
        )

    # Service is ready if all dependencies are healthy
    all_ready = all(checks.values())

    if not all_ready:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not ready",
                "checks": checks,
                "message": "Service dependencies not available"
            }
        )

    return {
        "status": "ready",
        "checks": checks
    }
