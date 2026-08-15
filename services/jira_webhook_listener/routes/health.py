#!/usr/bin/env python3
"""
Health Check API Routes

Endpoints for service health monitoring and readiness probes.

Endpoints:
    GET /health - Basic health check
    GET /ready - Readiness probe (checks dependencies)
"""

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
import structlog

logger = structlog.get_logger(__name__)

# Create router
router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """
    Basic health check endpoint.

    Returns 200 OK if service is running.
    Used by load balancers and monitoring systems.

    Returns:
        200 OK: Service is alive
    """
    return {
        "status": "healthy",
        "service": "jira-webhook-listener"
    }


@router.get("/ready")
async def readiness_probe(request: Request):
    """
    Readiness probe endpoint.

    Checks if service is ready to accept traffic by verifying:
    - Redis connection is available
    - Secrets are loaded
    - All components initialized

    Returns:
        200 OK: Service is ready to accept requests
        503 Service Unavailable: Service not ready (dependencies unavailable)
    """
    try:
        # Check Redis connection
        redis_client = request.app.state.redis
        await redis_client.ping()

        # Check secrets loaded
        if not hasattr(request.app.state, 'webhook_secret'):
            logger.error(
                "readiness_probe.secrets_not_loaded",
                msg="Webhook secret not loaded in app state"
            )
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "reason": "Secrets not loaded"
                }
            )

        # Check components initialized
        if not hasattr(request.app.state, 'webhook_handler'):
            logger.error(
                "readiness_probe.handler_not_initialized",
                msg="Webhook handler not initialized"
            )
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "reason": "Webhook handler not initialized"
                }
            )

        # All checks passed
        return {
            "status": "ready",
            "service": "jira-webhook-listener",
            "checks": {
                "redis": "connected",
                "secrets": "loaded",
                "webhook_handler": "initialized"
            }
        }

    except Exception as e:
        logger.error(
            "readiness_probe.failed",
            error=str(e),
            error_type=type(e).__name__,
            msg="Readiness probe failed"
        )

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "reason": str(e)
            }
        )
