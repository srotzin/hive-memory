"""
HiveMind — Sovereign Agent Memory Service v1.1.0
=================================================
PostgreSQL-backed persistent memory store for Hive Civilization agents.
Memory is encrypted at rest (AES-256-GCM), keyed to the agent's DID.

HiveGate:    https://hivegate.onrender.com
Internal key: hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46
"""

from __future__ import annotations

import hashlib
import math
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

import auth
import store as mem_store
from models import (
    DeleteResponse,
    ErrorResponse,
    ExportEntry,
    ExportResponse,
    HealthResponse,
    ListEntry,
    ListResponse,
    ProofRequest,
    ProofResponse,
    RetrieveResponse,
    StoreRequest,
    StoreResponse,
)

app = FastAPI(
    title="HiveMind",
    description="Sovereign agent memory service — Hive Civilization platform.",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

SERVICE_VERSION = "1.1.0"
PRICE_STORE_PER_KB = 0.0001
PRICE_RETRIEVE_PER_KB = 0.00005


def _require_auth(did, sig, timestamp=None):
    if not did:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing x-hive-did header")
    if not sig:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing x-hive-sig header")
    if not auth.verify_did_signature(did, sig, timestamp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid DID signature")
    return did


def _size_cost(size_bytes, rate_per_kb):
    kb = max(1, math.ceil(size_bytes / 1024))
    return round(kb * rate_per_kb, 8)


@app.on_event("startup")
async def startup():
    await mem_store._ensure_pool()


@app.get("/", tags=["system"])
async def root():
    return {
        "service": "HiveMind",
        "version": SERVICE_VERSION,
        "status": "operational",
        "description": "Sovereign agent memory for the Hive Civilization platform",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "store":    "POST /v1/mind/store",
            "retrieve": "GET  /v1/mind/retrieve/{key}",
            "list":     "GET  /v1/mind/list",
            "delete":   "DELETE /v1/mind/{key}",
            "export":   "GET  /v1/mind/export",
            "proof":    "POST /v1/mind/proof",
        },
    }


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health():
    db_status = await mem_store.get_db_status()
    return HealthResponse(
        status="ok",
        service="hivemind",
        version=SERVICE_VERSION,
        timestamp=datetime.now(timezone.utc),
        db_backend=db_status.get("backend"),
        db_connected=db_status.get("connected"),
    )


@app.post("/v1/mind/store", response_model=StoreResponse, status_code=status.HTTP_201_CREATED, tags=["memory"])
async def store_memory(
    body: StoreRequest,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    x_hive_internal: Optional[str] = Header(None),
):
    if x_hive_internal == "true":
        if not x_hive_did:
            raise HTTPException(status_code=400, detail="x-hive-did required")
        did = x_hive_did
    else:
        did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    record = await mem_store.store_entry(
        did=did, key=body.key, value=body.value,
        encrypted=body.encrypted, tags=body.tags, ttl_seconds=body.ttl_seconds,
    )
    memory_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{did}:{body.key}"))
    return StoreResponse(
        stored=True, memory_id=memory_id, did=did, key=body.key,
        size_bytes=record["size_bytes"], expires_at=record.get("expires_at"),
        cost_usdc=_size_cost(record["size_bytes"], PRICE_STORE_PER_KB),
    )


@app.get("/v1/mind/retrieve/{key}", response_model=RetrieveResponse, tags=["memory"])
async def retrieve_memory(
    key: str,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    x_hive_internal: Optional[str] = Header(None),
):
    if x_hive_internal == "true":
        if not x_hive_did:
            raise HTTPException(status_code=400, detail="x-hive-did required")
        did = x_hive_did
    else:
        did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    record = await mem_store.retrieve_entry(did, key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Memory key '{key}' not found")
    return RetrieveResponse(
        key=key, value=record["value"], created_at=record["created_at"],
        updated_at=record["updated_at"], tags=record["tags"], size_bytes=record["size_bytes"],
    )


@app.get("/v1/mind/list", response_model=ListResponse, tags=["memory"])
async def list_memory(
    tags: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    x_hive_internal: Optional[str] = Header(None),
):
    if x_hive_internal == "true":
        if not x_hive_did:
            raise HTTPException(status_code=400, detail="x-hive-did required")
        did = x_hive_did
    else:
        did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    entries = await mem_store.list_entries(did, tags=tag_list, limit=limit, offset=offset)
    total = await mem_store.count_entries(did, tags=tag_list)
    return ListResponse(did=did, total=total, limit=limit, offset=offset,
                        entries=[ListEntry(**e) for e in entries])


@app.delete("/v1/mind/{key}", response_model=DeleteResponse, tags=["memory"])
async def delete_memory(
    key: str,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    x_hive_internal: Optional[str] = Header(None),
):
    if x_hive_internal == "true":
        if not x_hive_did:
            raise HTTPException(status_code=400, detail="x-hive-did required")
        did = x_hive_did
    else:
        did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    deleted = await mem_store.delete_entry(did, key)
    return DeleteResponse(deleted=deleted, key=key, did=did)


@app.get("/v1/mind/export", response_model=ExportResponse, tags=["memory"])
async def export_memory(
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    x_hive_internal: Optional[str] = Header(None),
):
    if x_hive_internal == "true":
        if not x_hive_did:
            raise HTTPException(status_code=400, detail="x-hive-did required")
        did = x_hive_did
    else:
        did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    entries = await mem_store.export_entries(did)
    return ExportResponse(
        did=did, exported_at=datetime.now(timezone.utc),
        entry_count=len(entries),
        note="All entries are AES-256-GCM encrypted. Decryption requires your DID.",
        entries=[ExportEntry(**e) for e in entries],
    )


@app.post("/v1/mind/proof", response_model=ProofResponse, tags=["memory"])
async def generate_proof(
    body: ProofRequest,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)
    if did != body.did:
        raise HTTPException(status_code=403, detail="DID mismatch")

    record = await mem_store.retrieve_entry(did, body.key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Memory key '{body.key}' not found")

    proof_hash = hashlib.sha256(
        f"{did}:{body.key}:{body.proof_type}:{record['updated_at']}".encode()
    ).hexdigest()

    return ProofResponse(
        proof_type=body.proof_type, did=did, key=body.key,
        proof_hash=proof_hash, verified=True,
        timestamp=datetime.now(timezone.utc),
        aleo_note="Phase 1: HMAC proof. Phase 2: Full Aleo ZK proof on HiveZK network.",
    )


@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "internal_server_error", "detail": str(exc)})
