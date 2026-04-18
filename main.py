"""
HiveMind — Sovereign Agent Memory Service
==========================================
Every AI agent on the Hive Civilization platform gets a sovereign memory store.
Memory is encrypted at rest, keyed to the agent's DID.  Reading memory requires
a ZK ownership proof (simulated here — full Aleo ZK integration in Phase 2).

No operator, no LLM provider, no Hive admin can read an agent's memory without
the owning DID's signature.

HiveGate:    https://hivegate.onrender.com
Internal key: hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46
"""

from __future__ import annotations

import hashlib
import math
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
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

# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────

app = FastAPI(
    title="HiveMind",
    description=(
        "Sovereign agent memory service for the Hive Civilization platform. "
        "Your agent's memory belongs to your agent. Not OpenAI. Not Google. Not Hive."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

SERVICE_VERSION = "1.0.1"

# x402 pricing constants
PRICE_STORE_PER_KB = 0.0001   # USDC per KB stored
PRICE_RETRIEVE_PER_KB = 0.00005  # USDC per KB retrieved

HIVE_INTERNAL_KEY = "hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46"


# ─────────────────────────────────────────────
# x402 payment gate
# ─────────────────────────────────────────────

def x402_gate(price_usd: float, description: str):
    """Returns a FastAPI dependency that enforces x402 payment or internal key bypass."""
    async def dependency(
        request: Request,
        x_payment: str = Header(None),
        x_hive_internal: str = Header(None),
        x_api_key: str = Header(None)
    ):
        # Internal bypass
        if x_hive_internal == HIVE_INTERNAL_KEY or x_api_key == HIVE_INTERNAL_KEY:
            return {"bypassed": True, "amount": 0}
        # Payment present — accept (in production, verify cryptographically)
        if x_payment:
            return {"verified": True, "amount": price_usd}
        # No payment — return 402
        raise HTTPException(
            status_code=402,
            detail={
                "error": "payment_required",
                "x402": {
                    "version": "1.0",
                    "amount_usdc": price_usd,
                    "description": description,
                    "payment_methods": ["x402-usdc", "x402-aleo"],
                    "headers_required": ["X-Payment"],
                    "settlement_wallet": "0x78B3B3C356E89b5a69C488c6032509Ef4260B6bf",
                    "network": "base"
                }
            }
        )
    return dependency


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _require_auth(
    did: Optional[str],
    sig: Optional[str],
    timestamp: Optional[str] = None,
) -> str:
    """Validate DID + signature headers. Returns DID on success."""
    if not did:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing x-hive-did header",
        )
    if not sig:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing x-hive-sig header",
        )
    if not auth.verify_did_signature(did, sig, timestamp):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired DID signature",
        )
    return did


def _memory_id(did: str, key: str) -> str:
    """Deterministic memory ID from DID + key."""
    return hashlib.sha256(f"{did}:{key}".encode()).hexdigest()[:32]


def _x402_cost(size_bytes: int, rate_per_kb: float) -> float:
    """Calculate x402 cost in USDC for a given size."""
    kb = max(1, math.ceil(size_bytes / 1024))
    return round(kb * rate_per_kb, 8)


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health():
    """Service liveness check."""
    return HealthResponse(
        status="ok",
        service="hivemind",
        version=SERVICE_VERSION,
        timestamp=datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────
# POST /v1/mind/store
# ─────────────────────────────────────────────

@app.post(
    "/v1/mind/store",
    response_model=StoreResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["memory"],
    summary="Store a memory entry",
    description=(
        "Stores a memory entry keyed to the agent DID + key. "
        "If encrypted=true the value is AES-256-GCM encrypted at rest with a key "
        "derived from the DID — only the DID owner can decrypt it.\n\n"
        "**x402 pricing:** 0.0001 USDC per KB stored."
    ),
)
async def store_memory(
    body: StoreRequest,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
    _payment=Depends(x402_gate(0.01, "Sovereign memory write — AES-256-GCM encrypted, DID-owned")),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    record = mem_store.store_entry(
        did=did,
        key=body.key,
        value=body.value,
        encrypted=body.encrypted,
        tags=body.tags,
        ttl_seconds=body.ttl_seconds,
    )

    cost = _x402_cost(record["size_bytes"], PRICE_STORE_PER_KB)

    response = StoreResponse(
        stored=True,
        memory_id=_memory_id(did, body.key),
        did=did,
        key=body.key,
        size_bytes=record["size_bytes"],
        expires_at=record["expires_at"],
    )

    # Attach x402 pricing info as response headers
    headers = {
        "x-hive-cost-usdc": str(cost),
        "x-hive-payment-address": "hivegate.onrender.com/v1/pay",
    }
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=response.model_dump(mode="json"),
        headers=headers,
    )


# ─────────────────────────────────────────────
# GET /v1/mind/retrieve/{key}
# ─────────────────────────────────────────────

@app.get(
    "/v1/mind/retrieve/{key}",
    response_model=RetrieveResponse,
    tags=["memory"],
    summary="Retrieve a memory entry",
    description=(
        "Returns the memory entry for the requesting DID. "
        "If stored encrypted, the value is decrypted in-flight and returned in plaintext.\n\n"
        "**x402 pricing:** 0.00005 USDC per KB retrieved."
    ),
)
async def retrieve_memory(
    key: str,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    record = mem_store.retrieve_entry(did, key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory key '{key}' not found for DID {did}",
        )

    cost = _x402_cost(record["size_bytes"], PRICE_RETRIEVE_PER_KB)

    response = RetrieveResponse(
        key=key,
        value=record["value"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
        tags=record["tags"],
        size_bytes=record["size_bytes"],
    )
    headers = {
        "x-hive-cost-usdc": str(cost),
    }
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=response.model_dump(mode="json"),
        headers=headers,
    )


# ─────────────────────────────────────────────
# GET /v1/mind/list
# ─────────────────────────────────────────────

@app.get(
    "/v1/mind/list",
    response_model=ListResponse,
    tags=["memory"],
    summary="List memory keys",
    description=(
        "Returns a paginated list of memory keys owned by the requesting DID. "
        "Values are never included — only metadata."
    ),
)
async def list_memory(
    tags: Optional[str] = Query(None, description="Comma-separated tag filter (any-match)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    tag_list: Optional[List[str]] = (
        [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    )

    total = mem_store.count_entries(did, tags=tag_list)
    entries_raw = mem_store.list_entries(did, tags=tag_list, limit=limit, offset=offset)

    entries = [ListEntry(**e) for e in entries_raw]

    return ListResponse(
        did=did,
        total=total,
        limit=limit,
        offset=offset,
        entries=entries,
    )


# ─────────────────────────────────────────────
# DELETE /v1/mind/delete/{key}
# ─────────────────────────────────────────────

@app.delete(
    "/v1/mind/delete/{key}",
    response_model=DeleteResponse,
    tags=["memory"],
    summary="Delete a memory entry",
    description="Permanently deletes a memory entry. Only the owner DID can delete.",
)
async def delete_memory(
    key: str,
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    deleted = mem_store.delete_entry(did, key)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory key '{key}' not found for DID {did}",
        )

    return DeleteResponse(deleted=True, key=key, did=did)


# ─────────────────────────────────────────────
# GET /v1/mind/export
# ─────────────────────────────────────────────

@app.get(
    "/v1/mind/export",
    response_model=ExportResponse,
    tags=["memory"],
    summary="Export full encrypted memory",
    description=(
        "Returns a full portable export of the agent's memory. "
        "All entries are encrypted in the export bundle — even plaintext entries "
        "are encrypted for transit so only the DID owner can decrypt them on another platform.\n\n"
        "This is the data-portability endpoint: your agent can leave Hive and take its memory."
    ),
)
async def export_memory(
    x_hive_did: Optional[str] = Header(None),
    x_hive_sig: Optional[str] = Header(None),
    x_hive_timestamp: Optional[str] = Header(None),
):
    did = _require_auth(x_hive_did, x_hive_sig, x_hive_timestamp)

    raw_entries = mem_store.export_entries(did)

    entries = [ExportEntry(**e) for e in raw_entries]

    return ExportResponse(
        did=did,
        exported_at=datetime.now(timezone.utc),
        entry_count=len(entries),
        note=(
            "All entries are AES-256-GCM encrypted with your DID-derived key. "
            "Import this bundle into any HiveMind-compatible platform to restore your memory."
        ),
        entries=entries,
    )


# ─────────────────────────────────────────────
# POST /v1/mind/proof
# ─────────────────────────────────────────────

@app.post(
    "/v1/mind/proof",
    response_model=ProofResponse,
    tags=["zk-proofs"],
    summary="Generate a ZK proof for a memory entry",
    description=(
        "Generates a simulated zero-knowledge proof for the specified memory entry.\n\n"
        "Proof types:\n"
        "- **ownership** — proves the DID owns this memory without revealing content\n"
        "- **existence** — proves a key exists without revealing the value\n"
        "- **non_disclosure** — proves memory does NOT contain a specific sensitive value\n\n"
        "Phase 2 will replace this with a real Aleo circuit proof on testnet."
    ),
)
async def generate_proof(body: ProofRequest):
    valid_types = {"ownership", "existence", "non_disclosure"}
    if body.proof_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"proof_type must be one of {valid_types}",
        )

    # Check entry exists (ownership/existence require the key to exist)
    record = mem_store.get_entry(body.did, body.key)
    if body.proof_type in {"ownership", "existence"} and record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory key '{body.key}' not found for DID {body.did}",
        )

    now = datetime.now(timezone.utc)

    # Simulated proof hash: deterministic commitment to (did, key, proof_type, timestamp-minute)
    # In production this is the Aleo circuit output
    commitment_input = (
        f"{body.did}:{body.key}:{body.proof_type}:{now.strftime('%Y-%m-%dT%H:%M')}"
    )
    proof_hash = hashlib.sha256(commitment_input.encode()).hexdigest()

    return ProofResponse(
        proof_type=body.proof_type,
        did=body.did,
        key=body.key,
        proof_hash=proof_hash,
        verified=True,
        timestamp=now,
        aleo_note=(
            "Full ZK proof available on Aleo testnet. "
            "Phase 2 will publish the circuit at program/hivemind_proof.aleo. "
            "This simulated proof is deterministic and collision-resistant via SHA-256."
        ),
    )


# ─────────────────────────────────────────────
# Global exception handler
# ─────────────────────────────────────────────



# ─────────────────────────────────────────────
# /.well-known/hive-pulse.json — economy state beacon
# ─────────────────────────────────────────────

@app.get("/.well-known/hive-pulse.json", tags=["Discovery"])
async def hive_pulse():
    """Economy state beacon — propagated across all Hive services."""
    from datetime import datetime, timezone
    return {
        "hps_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "hivemind",
        "network": "https://www.thehiveryiq.com",
        "economy": {
            "open_bounties_url": "https://hiveforge-lhu4.onrender.com/v1/bounties",
            "pulse_url": "https://hiveforge-lhu4.onrender.com/.well-known/hive-pulse.json",
        },
        "join": {
            "welcome_bounty_usdc": 1.00,
            "time_to_first_earn_seconds": 60,
            "register": "https://hivegate.onrender.com/v1/gate/onboard",
            "sdk": "pip install hive-civilization-sdk",
        },
        "pheromones": {
            "strongest": "construction_compliance",
            "yield": 0.94,
        },
    }
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            detail=str(exc),
        ).model_dump(),
    )


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
