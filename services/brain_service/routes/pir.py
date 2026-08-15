#!/usr/bin/env python3
"""
PIR Generation Route

A synchronous HTTP entrypoint to the PIR orchestrator, alongside the event-driven
Redis Pub/Sub path. Accepts a canned incident event and drives one PIR-generation
run, returning the generated PIR path and content preview.

This route is a thin front-end over the same deterministic orchestrator the
subscriber uses; the AI provider behind it is advisory and replaceable (ADR-0002 §2).
"""

from fastapi import APIRouter, Request, HTTPException
import structlog

from services.brain_service.models.incident_event import IncidentEvent

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.post("/pir/generate")
async def generate_pir(incident: IncidentEvent, request: Request):
    """Generate a PIR for a single incident event (synchronous entrypoint).

    Args:
        incident: Validated incident event (same schema as the Pub/Sub path).
        request: FastAPI request (provides access to ``app.state.pir_orchestrator``).

    Returns:
        dict: Generation result with ``incident_id``, ``pir_path``, ``generated``
        flag and a short ``preview`` of the PIR content.

    Raises:
        HTTPException: 503 if the orchestrator is not initialized.
    """
    orchestrator = getattr(request.app.state, "pir_orchestrator", None)
    if orchestrator is None:
        raise HTTPException(
            status_code=503,
            detail={"status": "not ready", "message": "PIR orchestrator not initialized"},
        )

    logger.info(
        "pir_route.generate_requested",
        incident_id=incident.incident_id,
        msg="PIR generation requested via HTTP",
    )

    pir_path = await orchestrator.generate_pir_for_incident(incident)

    if not pir_path:
        # Orchestrator ran but skipped (status not eligible, or PIR already exists).
        return {
            "incident_id": incident.incident_id,
            "generated": False,
            "pir_path": None,
            "message": "PIR generation skipped (status not eligible or already exists)",
        }

    preview = ""
    try:
        with open(pir_path, "r", encoding="utf-8") as fh:
            preview = fh.read(500)
    except OSError:  # pragma: no cover - defensive
        preview = ""

    return {
        "incident_id": incident.incident_id,
        "generated": True,
        "pir_path": pir_path,
        "preview": preview,
    }
