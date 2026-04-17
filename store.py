"""
HiveMind — Sovereign in-memory store with AES-256 encryption.

Structure:
  _store[did][key] = {
      value:        Any,            # raw (after decrypt) or ciphertext bytes
      encrypted:    bool,
      created_at:   datetime,
      updated_at:   datetime,
      tags:         list[str],
      size_bytes:   int,
      expires_at:   datetime | None,
  }

Encryption: AES-256-GCM, key derived from DID via SHA-256.
No operator or external party can read encrypted values without the DID.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────
# In-memory store
# ─────────────────────────────────────────────

_store: Dict[str, Dict[str, dict]] = {}


# ─────────────────────────────────────────────
# AES-256-GCM helpers
# ─────────────────────────────────────────────

def _derive_key(did: str) -> bytes:
    """Derive a 256-bit AES key deterministically from a DID via SHA-256."""
    return hashlib.sha256(did.encode("utf-8")).digest()


def encrypt_value(did: str, value: Any) -> str:
    """
    Encrypt any JSON-serialisable value with AES-256-GCM.
    Returns base64-encoded string: nonce (12 bytes) || ciphertext+tag.
    """
    key = _derive_key(did)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(value, default=str).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, did.encode("utf-8"))
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def decrypt_value(did: str, blob_b64: str) -> Any:
    """
    Decrypt a base64 blob previously produced by encrypt_value.
    Raises ValueError if the DID doesn't match (authentication tag fails).
    """
    key = _derive_key(did)
    aesgcm = AESGCM(key)
    blob = base64.b64decode(blob_b64)
    nonce, ciphertext = blob[:12], blob[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, did.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))


# ─────────────────────────────────────────────
# Store operations
# ─────────────────────────────────────────────

def store_entry(
    did: str,
    key: str,
    value: Any,
    encrypted: bool,
    tags: List[str],
    ttl_seconds: Optional[int],
) -> dict:
    """
    Upsert a memory entry for (did, key).
    Returns the stored record.
    """
    now = datetime.now(timezone.utc)

    if encrypted:
        stored_value = encrypt_value(did, value)
    else:
        stored_value = value

    # Measure size against JSON representation of original value
    size_bytes = len(json.dumps(value, default=str).encode("utf-8"))

    expires_at: Optional[datetime] = None
    if ttl_seconds is not None:
        from datetime import timedelta
        expires_at = now + timedelta(seconds=ttl_seconds)

    if did not in _store:
        _store[did] = {}

    existing = _store[did].get(key)
    created_at = existing["created_at"] if existing else now

    record = {
        "value": stored_value,
        "encrypted": encrypted,
        "created_at": created_at,
        "updated_at": now,
        "tags": tags,
        "size_bytes": size_bytes,
        "expires_at": expires_at,
    }
    _store[did][key] = record
    return record


def get_entry(did: str, key: str) -> Optional[dict]:
    """
    Retrieve a memory record. Returns None if not found or expired.
    Caller is responsible for decryption if needed.
    """
    record = _store.get(did, {}).get(key)
    if record is None:
        return None
    # Expiry check
    if record["expires_at"] and datetime.now(timezone.utc) > record["expires_at"]:
        delete_entry(did, key)
        return None
    return record


def retrieve_entry(did: str, key: str) -> Optional[dict]:
    """
    Retrieve and decrypt (if needed) a memory entry.
    Returns a dict with decrypted value, or None if not found/expired.
    """
    record = get_entry(did, key)
    if record is None:
        return None

    result = dict(record)
    if record["encrypted"]:
        result["value"] = decrypt_value(did, record["value"])
    return result


def list_entries(
    did: str,
    tags: Optional[List[str]] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[dict]:
    """
    List memory keys owned by a DID. Values are never returned here.
    Optionally filter by tags (any-match).
    """
    now = datetime.now(timezone.utc)
    did_store = _store.get(did, {})

    entries = []
    for key, record in did_store.items():
        # Skip expired
        if record["expires_at"] and now > record["expires_at"]:
            continue
        # Tag filter
        if tags:
            if not any(t in record["tags"] for t in tags):
                continue
        entries.append({
            "key": key,
            "tags": record["tags"],
            "size_bytes": record["size_bytes"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "encrypted": record["encrypted"],
            "expires_at": record["expires_at"],
        })

    # Sort by updated_at desc
    entries.sort(key=lambda e: e["updated_at"], reverse=True)
    return entries[offset: offset + limit]


def count_entries(did: str, tags: Optional[List[str]] = None) -> int:
    """Total non-expired entries for a DID, optionally filtered by tags."""
    return len(list_entries(did, tags=tags, limit=10_000, offset=0))


def delete_entry(did: str, key: str) -> bool:
    """Delete a memory entry. Returns True if it existed."""
    did_store = _store.get(did, {})
    if key in did_store:
        del did_store[key]
        return True
    return False


def export_entries(did: str) -> List[dict]:
    """
    Export all entries for a DID as encrypted blobs for portability.
    Plaintext entries are re-encrypted for export so the bundle is always opaque.
    """
    now = datetime.now(timezone.utc)
    did_store = _store.get(did, {})
    result = []

    for key, record in did_store.items():
        if record["expires_at"] and now > record["expires_at"]:
            continue

        if record["encrypted"]:
            encrypted_blob = record["value"]          # already encrypted
        else:
            encrypted_blob = encrypt_value(did, record["value"])  # encrypt for export

        result.append({
            "key": key,
            "encrypted_blob": encrypted_blob,
            "tags": record["tags"],
            "size_bytes": record["size_bytes"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "expires_at": record["expires_at"],
        })

    return result
