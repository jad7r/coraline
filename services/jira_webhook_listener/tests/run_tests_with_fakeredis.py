#!/usr/bin/env python3
"""
End-to-end test runner using FakeRedis (no Redis server required).

Boots the real FastAPI webhook listener in-process with an in-memory
``fakeredis`` backend, waits for the ``/health`` endpoint, then drives the full
security test suite from ``mock_jira_webhook_sender`` over real HTTP.

The service code is NOT modified for tests: this launcher monkeypatches
``redis.asyncio.from_url`` so the app's lifespan gets a fakeredis client instead
of connecting to a real Redis server.

Run from the repository root:

    JIRA_WEBHOOK_SECRET=test-webhook-secret \\
        python -m services.jira_webhook_listener.tests.run_tests_with_fakeredis
"""

import os
import sys
import threading
import time
import urllib.request

import fakeredis.aioredis

# The mock sender and app are imported as installed package modules; the service
# must be launched from the repository root so `services` is importable.
from services.jira_webhook_listener.tests.mock_jira_webhook_sender import (
    MockJiraWebhookSender,
)

TEST_SECRET = "test-webhook-secret"
# Use a dedicated CORELINE_TEST_PORT so an inherited production CORELINE_PORT does not
# force the test server onto a colliding port.
TEST_PORT = int(os.environ.get("CORELINE_TEST_PORT", "8099"))
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


def _install_fakeredis():
    """Patch redis.asyncio.from_url so the app uses an in-memory backend.

    Returns a callable that restores the original ``from_url`` so the global
    module state is not left mutated after the test run.
    """
    import redis.asyncio as redis_async

    original_from_url = redis_async.from_url
    _shared = fakeredis.aioredis.FakeRedis(decode_responses=True)

    def _fake_from_url(*args, **kwargs):
        return _shared

    redis_async.from_url = _fake_from_url

    def _restore():
        redis_async.from_url = original_from_url

    return _restore


def _wait_for_health(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def main() -> int:
    # Configure the service via environment (secret from env, per directive).
    os.environ.setdefault("CORELINE_ENVIRONMENT", "dev")
    os.environ.setdefault("JIRA_WEBHOOK_SECRET", TEST_SECRET)
    # Force the service port to the isolated test port for this run.
    os.environ["CORELINE_PORT"] = str(TEST_PORT)

    print("=" * 80)
    print("Coreline Webhook Listener - End-to-End Test with FakeRedis")
    print("=" * 80)
    print()

    restore_redis = _install_fakeredis()

    # Import uvicorn and the app AFTER patching redis.
    import uvicorn
    from services.jira_webhook_listener.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=TEST_PORT, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        print(f"Waiting for {BASE_URL}/health ...")
        if not _wait_for_health():
            print("ERROR: service did not become healthy in time")
            return 1
        print("Service is healthy.\n")

        sender = MockJiraWebhookSender(
            target_url=f"{BASE_URL}/webhook", secret=TEST_SECRET
        )
        sender.run_test_scenarios()
        return 0
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        restore_redis()
        print("\nServer stopped.")


if __name__ == "__main__":
    sys.exit(main())
