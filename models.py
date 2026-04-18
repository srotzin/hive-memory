from __future__ import annotations
from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field

class StoreRequest(BaseModel):
    key: str
    value: Any
    ttl_seconds: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    encrypted: bool = True

class ProofRequest(BaseModel):
    did: str
    key: str
    proof_type: str

class StoreResponse(BaseModel):
    stored: bool
    memory_id: str
    did: str
    key: str
    size_bytes: int
    expires_at: Optional[datetime]
    cost_usdc: Optional[float] = None

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
    encrypted_blob: str
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
    db_backend: Optional[str] = None
    db_connected: Optional[bool] = None

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
