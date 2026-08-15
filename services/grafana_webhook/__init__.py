"""
services.grafana_webhook — Grafana IRM webhook receiver (revived under ADR-0003).

Receives Grafana IRM webhooks and syncs them into Coreline. Signature-verified with
HMAC-SHA256 over the raw request body using the ``X-Grafana-Signature`` header.
"""
