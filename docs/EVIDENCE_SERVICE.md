# Local evidence service boundary

The local API now exposes a tenant-partitioned evidence service:

- `POST /v1/evidence/append` accepts a typed event payload and appends it to that tenant's SHA-256 chain.
- `POST /v1/evidence/query` returns only records from the requested tenant, optionally filtered by event type.
- `POST /v1/evidence/verify` verifies sequence, previous-record links, evidence hashes, and record hashes.

Inventory observations, graph node/edge writes, drift evaluations, verification reports, and controlled workflow transitions are appended automatically by the local API. By default, the service keeps an in-memory chain. Set `A2Z_EVIDENCE_LEDGER_PATH` to a file inside an existing private directory to enable restart-persistent JSONL storage. The file is created with owner-only permissions; an existing file with broader permissions, a symlink, or an invalid chain causes startup or access to fail closed.

The file-backed API ledger and `scripts/evidence-ledger.py` use the same record format and tenant-specific sequence/hash chains. The service still does not sign evidence, export it, authorize actions, call providers, mint credentials, or execute changes.
