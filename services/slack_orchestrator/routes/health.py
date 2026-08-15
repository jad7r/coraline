#!/usr/bin/env python3
"""
Health Check Endpoints

Provides liveness and readiness probes for Kubernetes/Cloud Run orchestration.
"""

from fastapi import APIRouter, Request, HTTPException
import redis.asyncio as redis
from slack_sdk.errors import SlackApiError
import structlog

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
        "service": "slack-orchestrator"
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """
    Readiness probe endpoint.

    Returns HTTP 200 if service is ready to handle requests.
    Checks both Redis connectivity and Slack authentication; returns 503 if
    either dependency is unavailable.

    Args:
        request: FastAPI request object (provides access to app.state)

    Returns:
        dict: Readiness status

    Raises:
        HTTPException: 503 if service is not ready
    """
    checks = {
        "redis": False,
        "slack": False
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

    # Check Slack (auth test)
    try:
        auth_response = request.app.state.slack.auth_test()
        if auth_response.get('ok'):
            checks["slack"] = True
    except (SlackApiError, AttributeError) as e:
        logger.warning(
            "health.slack_check_failed",
            error=str(e),
            msg="Slack health check failed"
        )

    # Service is ready if both dependencies are healthy
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
