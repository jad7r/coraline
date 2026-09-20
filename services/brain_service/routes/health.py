#!/usr/bin/env python3
"""
Health Check Endpoints

Provides liveness and readiness probes for Kubernetes/Cloud Run orchestration.
"""

from fastapi import APIRouter, Request, HTTPException
import redis.asyncio as redis
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
        "service": "coreline-brain-service"
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """
    Readiness probe endpoint.

    Returns HTTP 200 if service is ready to handle requests.
    Checks:
    - Redis connectivity
    - The provider used by the orchestrator initialized successfully

    Provider configuration is checked at startup, without an upstream API call.

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
            error=type(e).__name__,
            msg="Redis health check failed"
        )

    # Startup validated credentials and constructed the provider used for work.
    # Re-reading mutable environment/keychain state would describe a different
    # configuration from that captured by the active provider.
    orchestrator = getattr(request.app.state, "pir_orchestrator", None)
    checks["credentials"] = bool(orchestrator is not None and
                                 getattr(orchestrator, "pir_provider", None) is not None)
    checks["provider"] = checks["credentials"]

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
