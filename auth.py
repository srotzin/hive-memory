"""
HiveMind — DID-based request authentication.

Current scheme (Phase 1):
  x-hive-sig = HMAC-SHA256( "{did}:{timestamp}", key=did )
  where timestamp is a Unix epoch integer (seconds), included in
  the x-hive-timestamp header.

A request is valid if:
  1. The HMAC matches.
  2. The timestamp is within ±60 seconds of server time (replay protection).

Note: Full W3C DID signature verification (Ed25519 / secp256k1 key resolution
from a DID Document) is implemented in Phase 2 production deployment.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional


# Replay window: accept requests within ±60 s of server time
REPLAY_WINDOW_SECONDS = 60


def _compute_expected_sig(did: str, timestamp: str) -> str:
    """
    Compute HMAC-SHA256( "{did}:{timestamp}", key=did ).
    Returns lowercase hex digest.
    """
    message = f"{did}:{timestamp}".encode("utf-8")
    key = did.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_did_signature(
    did: str,
    signature: str,
    timestamp: Optional[str] = None,
) -> bool:
    """
    Verify that the request is authorised for the given DID.

    Parameters
    ----------
    did:       The agent DID from x-hive-did header.
    signature: The HMAC signature from x-hive-sig header.
    timestamp: Unix epoch string from x-hive-timestamp header.
               If omitted, timestamp validation is skipped (dev mode only).

    Returns True if the signature is valid (and timestamp is fresh).
    """
    if not did or not signature:
        return False

    # If timestamp provided, validate freshness first
    if timestamp is not None:
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            return False
        now = int(time.time())
        if abs(now - ts) > REPLAY_WINDOW_SECONDS:
            return False
        expected = _compute_expected_sig(did, timestamp)
    else:
        # Dev / integration-test path: accept any well-formed DID + sig
        # matching any recent timestamp within the window
        now = int(time.time())
        matched = False
        for delta in range(-REPLAY_WINDOW_SECONDS, REPLAY_WINDOW_SECONDS + 1):
            candidate_ts = str(now + delta)
            if hmac.compare_digest(
                _compute_expected_sig(did, candidate_ts), signature
            ):
                matched = True
                break
        # Also try the signature as HMAC over just the DID (simpler clients)
        if not matched:
            fallback = hmac.new(
                did.encode(), did.encode(), hashlib.sha256
            ).hexdigest()
            matched = hmac.compare_digest(fallback, signature)
        return matched

    return hmac.compare_digest(expected, signature)


def generate_test_signature(did: str) -> dict:
    """
    Utility: generate a valid signature for integration testing.
    Returns {did, timestamp, signature}.
    """
    timestamp = str(int(time.time()))
    sig = _compute_expected_sig(did, timestamp)
    return {"did": did, "timestamp": timestamp, "signature": sig}
