"""
HiveMind — Pydantic models for all requests and responses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────

class StoreRequest(BaseModel):
    key: str = Field(..., description="Memory key (unique per DID)")
    value: Any = Field(..., description="Any JSON-serialisable value")
    ttl_seconds: Optional[int] = Field(None, description="Optional time-to-live in seconds")
    tags: List[str] = Field(default_factory=list, description="Optional tags for filtering")
    encrypted: bool = Field(True, description="Encrypt value at rest with DID-derived AES-256 key")


class ProofRequest(BaseModel):
    did: str = Field(..., description="Agent DID claiming ownership")
    key: str = Field(..., description="Memory key to prove")
    proof_type: str = Field(
        ...,
        description=(
            "Type of ZK proof: "
            "'ownership' | 'existence' | 'non_disclosure'"
        ),
    )


# ─────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────

class StoreResponse(BaseModel):
    stored: bool
    memory_id: str
    did: str
    key: str
    size_bytes: int
    expires_at: Optional[datetime]


class RetrieveResponse(BaseModel):
    key: str
    value: Any
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    size_bytes: int


class ListEntry(BaseModel):
    key: str
    tags: List[str]
    size_bytes: int
    created_at: datetime
    updated_at: datetime
    encrypted: bool
    expires_at: Optional[datetime]


class ListResponse(BaseModel):
    did: str
    total: int
    limit: int
    offset: int
    entries: List[ListEntry]


class DeleteResponse(BaseModel):
    deleted: bool
    key: str
    did: str


class ExportEntry(BaseModel):
    key: str
    encrypted_blob: str          # base64-encoded ciphertext (always encrypted in export)
    tags: List[str]
    size_bytes: int
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]


class ExportResponse(BaseModel):
    did: str
    exported_at: datetime
    entry_count: int
    note: str
    entries: List[ExportEntry]


class ProofResponse(BaseModel):
    proof_type: str
    did: str
    key: str
    proof_hash: str
    verified: bool
    timestamp: datetime
    aleo_note: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: datetime


# ─────────────────────────────────────────────
# Error model
# ─────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
