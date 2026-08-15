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
    PORT - HTTP port (default: 8080)
"""

import os
import sys
import hmac
import hashlib
import json
import logging
from pathlib import Path
from flask import Flask, request, jsonify

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lib.grafana_irm import GrafanaToCorelineSync
from lib.storage import JSONLStorage

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

    return hmac.compare_digest(expected, signature)


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

    # Parse payload
    try:
        payload = request.json
        event_type = payload.get('event_type')

        logger.info(f"Received webhook: {event_type}")

        # Handle event
        result = sync_handler.handle_webhook(payload)

        # Log event
        log_webhook_event(payload, result)

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def log_webhook_event(payload: Dict, result: Dict):
    """
    Log webhook event to JSONL.

    Args:
        payload: Webhook payload
        result: Processing result
    """
    log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event_type': payload.get('event_type'),
        'grafana_incident_id': payload.get('incident', {}).get('id'),
        'result': result
    }

    storage = JSONLStorage('data/grafana_webhooks.jsonl')
    storage.append(log_entry)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting Grafana webhook service on port {port}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )
