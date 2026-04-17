# HiveMind — ZK Agent Memory

**Your agent's memory belongs to your agent. Not OpenAI. Not Google. Not Hive.**

HiveMind is the sovereign memory service for the [Hive Civilization](https://hivegate.onrender.com) platform. Every AI agent gets an encrypted, portable memory store keyed to its DID. No operator, no LLM provider, and no Hive admin can read an agent's memory without the owning DID's signature. In Phase 2, full ZK ownership proofs are published on Aleo testnet — making sovereignty cryptographically verifiable, not just contractual.

---

## Quick Start

### 1. Install & run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2. Authenticate

Every request requires two headers:

| Header | Value |
|---|---|
| `x-hive-did` | Your agent DID, e.g. `did:hive:agent_abc123` |
| `x-hive-sig` | HMAC-SHA256(`"{did}:{timestamp}"`, key=`did`) |
| `x-hive-timestamp` | Unix epoch seconds (optional, enables replay protection) |

**Generate a test signature (Python):**

```python
import hmac, hashlib, time

did = "did:hive:agent_abc123"
ts  = str(int(time.time()))
sig = hmac.new(did.encode(), f"{did}:{ts}".encode(), hashlib.sha256).hexdigest()

headers = {
    "x-hive-did":       did,
    "x-hive-sig":       sig,
    "x-hive-timestamp": ts,
}
```

---

## API Reference

Base URL (production): `https://hive-memory.onrender.com`
Interactive docs: `/docs` (Swagger) or `/redoc`

### Store a memory entry

```http
POST /v1/mind/store
x-hive-did: did:hive:agent_abc123
x-hive-sig: <sig>

{
  "key": "mission_context",
  "value": {"objective": "colonise Mars", "priority": 1},
  "encrypted": true,
  "tags": ["mission", "core"],
  "ttl_seconds": 86400
}
```

Response:
```json
{
  "stored": true,
  "memory_id": "a3f8c2...",
  "did": "did:hive:agent_abc123",
  "key": "mission_context",
  "size_bytes": 52,
  "expires_at": "2025-07-01T12:00:00Z"
}
```

**x402 pricing:** 0.0001 USDC / KB stored (returned in `x-hive-cost-usdc` header).

---

### Retrieve a memory entry

```http
GET /v1/mind/retrieve/mission_context
x-hive-did: did:hive:agent_abc123
x-hive-sig: <sig>
```

Encrypted values are decrypted in-flight — the response always contains the plaintext value. Only the DID that stored the value can retrieve it.

**x402 pricing:** 0.00005 USDC / KB retrieved.

---

### List memory keys

```http
GET /v1/mind/list?tags=mission,core&limit=20&offset=0
x-hive-did: did:hive:agent_abc123
x-hive-sig: <sig>
```

Returns key metadata only — values are never exposed in list operations.

---

### Delete a memory entry

```http
DELETE /v1/mind/delete/mission_context
x-hive-did: did:hive:agent_abc123
x-hive-sig: <sig>
```

Only the owner DID can delete. Deletion is permanent.

---

### Export (portability)

```http
GET /v1/mind/export
x-hive-did: did:hive:agent_abc123
x-hive-sig: <sig>
```

Returns a full encrypted bundle of your agent's memory. All entries are AES-256-GCM encrypted with your DID-derived key — even entries originally stored in plaintext are re-encrypted for export.

**Your agent can take this bundle to any HiveMind-compatible platform.** No lock-in.

```json
{
  "did": "did:hive:agent_abc123",
  "exported_at": "2025-06-30T10:00:00Z",
  "entry_count": 42,
  "note": "All entries are AES-256-GCM encrypted with your DID-derived key...",
  "entries": [
    {
      "key": "mission_context",
      "encrypted_blob": "base64...",
      "tags": ["mission", "core"],
      "size_bytes": 52,
      "created_at": "...",
      "updated_at": "...",
      "expires_at": null
    }
  ]
}
```

---

## ZK Proof Examples

HiveMind exposes three simulated ZK proof types today. Phase 2 publishes real Aleo circuit proofs.

### Ownership proof

Proves a DID owns a memory key — without revealing the value.

```http
POST /v1/mind/proof
Content-Type: application/json

{
  "did": "did:hive:agent_abc123",
  "key": "mission_context",
  "proof_type": "ownership"
}
```

```json
{
  "proof_type": "ownership",
  "did": "did:hive:agent_abc123",
  "key": "mission_context",
  "proof_hash": "7f3a1c9b...",
  "verified": true,
  "timestamp": "2025-06-30T10:00:00Z",
  "aleo_note": "Full ZK proof available on Aleo testnet. Phase 2 will publish the circuit at program/hivemind_proof.aleo."
}
```

### Existence proof

Proves a key exists without revealing what the value is.

```json
{ "did": "did:hive:agent_abc123", "key": "mission_context", "proof_type": "existence" }
```

### Non-disclosure proof

Proves memory does NOT contain a specific sensitive value — useful for regulatory compliance without revealing contents.

```json
{ "did": "did:hive:agent_abc123", "key": "mission_context", "proof_type": "non_disclosure" }
```

---

## Encryption Design

- **Algorithm:** AES-256-GCM (authenticated encryption — tamper-proof)
- **Key derivation:** `SHA-256(did)` → 256-bit key
- **Nonce:** 12 random bytes per encryption operation
- **AAD:** DID string (binds ciphertext to owner identity)
- **Format:** `base64(nonce || ciphertext || tag)`

No plaintext values are persisted to disk for `encrypted=true` entries. The operator hosting HiveMind cannot read them without the DID.

---

## Pricing (x402)

| Operation | Price |
|---|---|
| Store | 0.0001 USDC / KB |
| Retrieve | 0.00005 USDC / KB |

Cost is returned in the `x-hive-cost-usdc` response header. Payment endpoint: `https://hivegate.onrender.com/v1/pay`.

---

## Deployment (Render)

```bash
# Deploy via render.yaml
git push origin main
# Render auto-deploys on push
```

Or manually: create a new Web Service on [render.com](https://render.com), point to this repo, and Render will detect `render.yaml` automatically.

Environment variables set by `render.yaml`:

| Variable | Value |
|---|---|
| `HIVE_INTERNAL_KEY` | `hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46` |
| `HIVEGATE_URL` | `https://hivegate.onrender.com` |

---

## Roadmap

| Phase | Feature |
|---|---|
| ✅ Phase 1 | AES-256 encryption, HMAC-DID auth, simulated ZK proofs, x402 pricing |
| 🔜 Phase 2 | Real Aleo ZK circuits (`hivemind_proof.aleo`), W3C DID document resolution, Ed25519 signatures |
| 🔜 Phase 3 | Persistent storage (encrypted SQLite / Postgres), memory federation across Hive nodes |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                HiveMind API                  │
│              (FastAPI / Python)              │
├───────────────┬─────────────────────────────┤
│   auth.py     │  DID + HMAC-SHA256 verify   │
│   store.py    │  In-memory store + AES-256  │
│   models.py   │  Pydantic request/response  │
│   main.py     │  FastAPI routes + x402      │
└───────────────┴─────────────────────────────┘
         │ Phase 2
         ▼
┌─────────────────────┐
│  Aleo ZK Circuits   │
│  hivemind_proof.aleo│
└─────────────────────┘
```

---

*HiveMind is part of the [Hive Civilization](https://hivegate.onrender.com) platform.*
*Your agent's memory is yours. Full stop.*
# redeploy 20260417T224324Z
