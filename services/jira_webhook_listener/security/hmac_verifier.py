#!/usr/bin/env python3
"""
HMAC Signature Verifier for Jira Webhooks

Implements Security Guardrail G2.1: Webhook Authentication
Verifies HMAC-SHA256 signatures on incoming Jira webhooks using constant-time
comparison to prevent timing attacks.

Security Requirements:
- Use constant-time comparison (hmac.compare_digest)
- Never log signature values or secrets
- Reject webhooks with missing/invalid signatures
- Support standard webhook signature formats
"""

import hmac
import hashlib
import structlog
from typing import Optional, Tuple

logger = structlog.get_logger(__name__)


class HMACVerifier:
    """Verifies HMAC signatures on Jira webhook payloads."""

    def __init__(self, secret: str):
        """
        Initialize HMAC verifier with webhook secret.

        Args:
            secret: Webhook secret from SecretsManager (string)
        """
        self.secret = secret.encode('utf-8')
        logger.info(
            "hmac_verifier.initialized",
            secret_length=len(self.secret),
            msg="HMAC verifier initialized (secret not logged)"
        )

    def verify(
        self,
        payload: bytes,
        signature_header: Optional[str]
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify HMAC signature matches expected value.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            payload: Raw webhook body (bytes)
            signature_header: Value from X-Hub-Signature or similar header
                             Expected format: "sha256=<hex_signature>"

        Returns:
            Tuple of (is_valid, error_message)
            - (True, None) if signature is valid
            - (False, error_message) if invalid or missing

        Security Notes:
            - Uses hmac.compare_digest() for constant-time comparison
            - Never logs actual signature values
            - Fails fast on missing signature header
        """
        # Check for missing signature
        if not signature_header:
            logger.warning(
                "hmac_verifier.missing_signature",
                msg="Webhook received without signature header"
            )
            return (False, "Missing signature header")

        # Extract signature from header
        # Support formats: "sha256=<hex>" or just "<hex>"
        if '=' in signature_header:
            try:
                algorithm, signature_hex = signature_header.split('=', 1)
                if algorithm.lower() != 'sha256':
                    logger.warning(
                        "hmac_verifier.unsupported_algorithm",
                        algorithm=algorithm,
                        msg="Webhook signature uses unsupported algorithm"
                    )
                    return (False, f"Unsupported signature algorithm: {algorithm}")
            except ValueError:
                logger.warning(
                    "hmac_verifier.malformed_signature",
                    msg="Webhook signature header malformed"
                )
                return (False, "Malformed signature header")
        else:
            signature_hex = signature_header

        # Validate signature format (hex string)
        try:
            # Attempt to decode hex - will raise ValueError if invalid
            bytes.fromhex(signature_hex)
        except ValueError:
            logger.warning(
                "hmac_verifier.invalid_hex",
                signature_length=len(signature_hex),
                msg="Webhook signature is not valid hex"
            )
            return (False, "Signature is not valid hexadecimal")

        # Compute expected HMAC signature
        expected_hmac = hmac.new(
            key=self.secret,
            msg=payload,
            digestmod=hashlib.sha256
        )
        expected_signature = expected_hmac.hexdigest()

        # Constant-time comparison (prevents timing attacks)
        is_valid = hmac.compare_digest(expected_signature, signature_hex)

        if is_valid:
            logger.info(
                "hmac_verifier.verification_success",
                payload_length=len(payload),
                msg="HMAC signature verified successfully"
            )
            return (True, None)
        else:
            logger.warning(
                "hmac_verifier.verification_failed",
                payload_length=len(payload),
                expected_length=len(expected_signature),
                received_length=len(signature_hex),
                msg="HMAC signature verification failed"
            )
            return (False, "HMAC signature verification failed")

    def verify_and_raise(self, payload: bytes, signature_header: Optional[str]):
        """
        Verify HMAC signature and raise exception if invalid.

        Convenience method for fail-fast verification.

        Args:
            payload: Raw webhook body (bytes)
            signature_header: Signature header value

        Raises:
            HMACVerificationError: If signature is invalid or missing
        """
        is_valid, error_message = self.verify(payload, signature_header)
        if not is_valid:
            raise HMACVerificationError(error_message)


class HMACVerificationError(Exception):
    """Raised when HMAC signature verification fails."""
    pass
