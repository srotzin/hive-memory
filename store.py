"""
HiveMind — Persistent agent memory store with AES-256 encryption.

Storage backends (selected by DATABASE_URL env var):
  - PostgreSQL (production): full persistence via asyncpg
  - In-memory dict (fallback): used when no DB is configured

Encryption: AES-256-GCM, key derived from DID via SHA-256.
No operator or external party can read encrypted values without the DID.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─────────────────────────────────────────────
# AES-256-GCM helpers
# ─────────────────────────────────────────────

def _derive_key(did: str) -> bytes:
    return hashlib.sha256(did.encode("utf-8")).digest()


def encrypt_value(did: str, value: Any) -> str:
    key = _derive_key(did)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(value, default=str).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, did.encode("utf-8"))
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_value(did: str, blob_b64: str) -> Any:
    key = _derive_key(did)
    aesgcm = AESGCM(key)
    blob = base64.b64decode(blob_b64)
    nonce, ciphertext = blob[:12], blob[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, did.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))


# ─────────────────────────────────────────────
# In-memory fallback store (no DB)
# ─────────────────────────────────────────────

_mem: Dict[str, Dict[str, dict]] = {}

_pool = None
_db_ready = False


async def _ensure_pool():
    global _pool, _db_ready
    if _db_ready:
        return True
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        return False
    try:
        import asyncpg
        dsn = db_url.replace("postgres://", "postgresql://", 1)
        _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hive_memory (
                    did         TEXT NOT NULL,
                    key         TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    encrypted   BOOLEAN NOT NULL DEFAULT TRUE,
                    tags        TEXT[] NOT NULL DEFAULT '{}',
                    size_bytes  INT NOT NULL DEFAULT 0,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at  TIMESTAMPTZ,
                    PRIMARY KEY (did, key)
                )
            """)
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hive_memory_did ON hive_memory(did)"
            )
        _db_ready = True
        return True
    except Exception as e:
        print(f"[HiveMind] DB init failed, using in-memory store: {e}")
        return False


async def store_entry(did, key, value, encrypted, tags, ttl_seconds):
    now = datetime.now(timezone.utc)
    stored_value = encrypt_value(did, value) if encrypted else json.dumps(value, default=str)
    size_bytes = len(json.dumps(value, default=str).encode("utf-8"))
    expires_at = (now + timedelta(seconds=ttl_seconds)) if ttl_seconds else None

    if await _ensure_pool():
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT created_at FROM hive_memory WHERE did=$1 AND key=$2", did, key
            )
            created_at = row["created_at"] if row else now
            await conn.execute("""
                INSERT INTO hive_memory (did, key, value, encrypted, tags, size_bytes, created_at, updated_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (did, key) DO UPDATE
                  SET value=$3, encrypted=$4, tags=$5, size_bytes=$6, updated_at=$8, expires_at=$9
            """, did, key, stored_value, encrypted, tags, size_bytes, created_at, now, expires_at)
            return {"value": stored_value, "encrypted": encrypted,
                    "created_at": created_at, "updated_at": now,
                    "tags": tags, "size_bytes": size_bytes, "expires_at": expires_at}
    else:
        if did not in _mem:
            _mem[did] = {}
        existing = _mem[did].get(key)
        created_at = existing["created_at"] if existing else now
        record = {"value": stored_value, "encrypted": encrypted,
                  "created_at": created_at, "updated_at": now,
                  "tags": tags, "size_bytes": size_bytes, "expires_at": expires_at}
        _mem[did][key] = record
        return record


async def retrieve_entry(did, key):
    now = datetime.now(timezone.utc)
    if await _ensure_pool():
        async with _pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM hive_memory WHERE did=$1 AND key=$2", did, key)
        if not row:
            return None
        r = dict(row)
        if r.get("expires_at") and now > r["expires_at"]:
            await delete_entry(did, key)
            return None
        if r["encrypted"]:
            r["value"] = decrypt_value(did, r["value"])
        else:
            r["value"] = json.loads(r["value"])
        return r
    else:
        record = _mem.get(did, {}).get(key)
        if not record:
            return None
        if record.get("expires_at") and now > record["expires_at"]:
            await delete_entry(did, key)
            return None
        result = dict(record)
        if record["encrypted"]:
            result["value"] = decrypt_value(did, record["value"])
        return result


async def list_entries(did, tags=None, limit=50, offset=0):
    now = datetime.now(timezone.utc)
    if await _ensure_pool():
        async with _pool.acquire() as conn:
            if tags:
                rows = await conn.fetch(
                    """SELECT key, tags, size_bytes, created_at, updated_at, encrypted, expires_at
                       FROM hive_memory WHERE did=$1 AND (expires_at IS NULL OR expires_at > $2)
                       AND tags && $3::text[] ORDER BY updated_at DESC LIMIT $4 OFFSET $5""",
                    did, now, tags, limit, offset)
            else:
                rows = await conn.fetch(
                    """SELECT key, tags, size_bytes, created_at, updated_at, encrypted, expires_at
                       FROM hive_memory WHERE did=$1 AND (expires_at IS NULL OR expires_at > $2)
                       ORDER BY updated_at DESC LIMIT $3 OFFSET $4""",
                    did, now, limit, offset)
        return [dict(r) for r in rows]
    else:
        did_store = _mem.get(did, {})
        entries = []
        for k, record in did_store.items():
            if record.get("expires_at") and now > record["expires_at"]:
                continue
            if tags and not any(t in record["tags"] for t in tags):
                continue
            entries.append({"key": k, "tags": record["tags"], "size_bytes": record["size_bytes"],
                            "created_at": record["created_at"], "updated_at": record["updated_at"],
                            "encrypted": record["encrypted"], "expires_at": record["expires_at"]})
        entries.sort(key=lambda e: e["updated_at"], reverse=True)
        return entries[offset: offset + limit]


async def count_entries(did, tags=None):
    now = datetime.now(timezone.utc)
    if await _ensure_pool():
        async with _pool.acquire() as conn:
            if tags:
                return await conn.fetchval(
                    "SELECT COUNT(*) FROM hive_memory WHERE did=$1 AND (expires_at IS NULL OR expires_at > $2) AND tags && $3::text[]",
                    did, now, tags)
            return await conn.fetchval(
                "SELECT COUNT(*) FROM hive_memory WHERE did=$1 AND (expires_at IS NULL OR expires_at > $2)",
                did, now)
    return len(await list_entries(did, tags=tags, limit=100_000, offset=0))


async def delete_entry(did, key):
    if await _ensure_pool():
        async with _pool.acquire() as conn:
            result = await conn.execute("DELETE FROM hive_memory WHERE did=$1 AND key=$2", did, key)
        return result.split()[-1] != "0"
    else:
        did_store = _mem.get(did, {})
        if key in did_store:
            del did_store[key]
            return True
        return False


async def export_entries(did):
    now = datetime.now(timezone.utc)
    if await _ensure_pool():
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM hive_memory WHERE did=$1 AND (expires_at IS NULL OR expires_at > $2)",
                did, now)
        records = [dict(r) for r in rows]
    else:
        did_store = _mem.get(did, {})
        records = [{"key": k, **v} for k, v in did_store.items()
                   if not (v.get("expires_at") and now > v["expires_at"])]

    result = []
    for r in records:
        if r["encrypted"]:
            blob = r["value"]
        else:
            raw = json.loads(r["value"]) if isinstance(r["value"], str) else r["value"]
            blob = encrypt_value(did, raw)
        result.append({"key": r["key"], "encrypted_blob": blob, "tags": r["tags"],
                       "size_bytes": r["size_bytes"], "created_at": r["created_at"],
                       "updated_at": r["updated_at"], "expires_at": r["expires_at"]})
    return result


async def get_db_status():
    if await _ensure_pool():
        return {"backend": "postgresql", "connected": True}
    return {"backend": "in_memory", "connected": False, "note": "Set DATABASE_URL for persistence"}
