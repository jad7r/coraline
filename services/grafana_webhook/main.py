#!/usr/bin/env python3
"""
Grafana IRM Webhook Service

Receives webhooks from Grafana IRM and syncs to Coreline.

Webhook Events:
    - incident.created - New Grafana incident
    - incident.acknowledged - Incident acknowledged
    - incident.resolved - Incident resolved
    - incident.note.created - Note added

Environment Variables:
    WEBHOOK_SECRET - Secret for webhook signature verification
    WEBHOOK_LOG_PATH - JSONL event-log path (default: data/grafana_webhooks.jsonl)
    PORT - HTTP port (default: 8080)
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict

from flask import Flask, request, jsonify
from werkzeug.exceptions import HTTPException

# TODO(ADR-0003 integration): swap to lib.grafana_irm / lib.storage
from services.grafana_webhook._lib_shim import GrafanaToCorelineSync, JSONLStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize sync handler
sync_handler = GrafanaToCorelineSync()

# Webhook secret for signature verification
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')

# Where received events are logged (JSONL). Override with WEBHOOK_LOG_PATH so
# runtime logs land in a known, deployment-controlled location.
WEBHOOK_LOG_PATH = os.environ.get('WEBHOOK_LOG_PATH', 'data/grafana_webhooks.jsonl')


def verify_signature(payload: bytes, signature: str) -> bool:
    """
    Verify webhook signature.

    Args:
        payload: Request body
        signature: Signature from header

    Returns:
        True if valid
    """
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET not set - skipping signature verification")
        return True

    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    # compare_digest raises TypeError on non-ASCII input; a malformed/hostile
    # header must be treated as a failed comparison, not a 500.
    try:
        return hmac.compare_digest(expected, signature)
    except TypeError:
        return False


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'grafana-webhook'})


@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Handle Grafana IRM webhooks.

    Expected payload:
    {
        "event_type": "incident.created",
        "incident": {
            "id": "abc123",
            "title": "Production outage",
            "severity": "critical",
            ...
        }
    }
    """
    # Verify signature
    signature = request.headers.get('X-Grafana-Signature', '')
    if not verify_signature(request.data, signature):
        logger.warning(f"Invalid signature from {request.remote_addr}")
        return jsonify({'error': 'Invalid signature'}), 401

    # Parse payload. Malformed input (bad JSON, wrong content-type, or a
    # non-object body) is a client error (400), distinct from an internal
    # failure while processing a well-formed event (500).
    try:
        payload = request.get_json(silent=True)
    except HTTPException:
        payload = None
    if not isinstance(payload, dict):
        logger.warning("Rejecting malformed webhook body from %s", request.remote_addr)
        return jsonify({'error': 'Malformed JSON body: expected a JSON object'}), 400

    event_type = payload.get('event_type')
    logger.info(f"Received webhook: {event_type}")

    # Handle event
    try:
        result = sync_handler.handle_webhook(payload)

        # Log event
        log_webhook_event(payload, result)

        return jsonify(result), 200

    except Exception:
        # Log full detail server-side; never leak internals to the caller.
        logger.error("Error processing webhook", exc_info=True)
        return jsonify({'error': 'Internal error processing webhook'}), 500


def log_webhook_event(payload: Dict, result: Dict):
    """
    Log webhook event to JSONL.

    Args:
        payload: Webhook payload
        result: Processing result
    """
    log_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'event_type': payload.get('event_type'),
        'grafana_incident_id': payload.get('incident', {}).get('id'),
        'result': result
    }

    storage = JSONLStorage(WEBHOOK_LOG_PATH)
    storage.append(log_entry)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting Grafana webhook service on port {port}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )
