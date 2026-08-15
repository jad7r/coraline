#!/usr/bin/env python3
"""
Webhook API Routes

FastAPI routes for receiving Jira webhooks.

Endpoints:
    POST /webhook - Receive and process Jira webhook
"""

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
import structlog

logger = structlog.get_logger(__name__)

# Create router
router = APIRouter(tags=["webhooks"])


@router.post("/webhook")
async def receive_webhook(request: Request):
    """
    Receive and process Jira webhook.

    Security Guardrails:
        - G2.1: HMAC signature verification
        - G2.2: Replay attack prevention
        - G2.3: Schema validation

    Request Headers:
        X-Hub-Signature: HMAC-SHA256 signature (format: "sha256=<hex>")

    Request Body:
        JSON webhook payload from Jira

    Returns:
        200 OK: Webhook processed successfully
        400 Bad Request: Invalid schema or stale webhook
        401 Unauthorized: HMAC verification failed
        409 Conflict: Duplicate webhook detected
        500 Internal Server Error: Unexpected error
    """
    # Extract signature header
    signature_header = request.headers.get("X-Hub-Signature")

    # Get source IP
    source_ip = request.client.host if request.client else None

    # Read raw body (needed for HMAC verification)
    payload_bytes = await request.body()

    # Get webhook handler from app state
    webhook_handler = request.app.state.webhook_handler

    # Process webhook with all security guardrails
    result = await webhook_handler.process_webhook(
        payload_bytes=payload_bytes,
        signature_header=signature_header,
        source_ip=source_ip
    )

    # Return response
    return JSONResponse(
        status_code=result.status_code,
        content=result.to_dict()
    )


@router.get("/")
async def root():
    """
    Root endpoint.

    Returns basic service information.
    """
    return {
        "service": "Coreline Jira Webhook Listener",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs"
    }
