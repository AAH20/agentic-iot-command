# Evidence Ledger

The local ledger is an append-only JSONL file with a SHA-256 chain. Each
record embeds one tenant-scoped evidence envelope, hashes the canonical
envelope, links to the previous record for that tenant, and is fsynced while
holding an exclusive file lock. Tenants share the JSONL file but have
independent sequence numbers and hash chains.

Append a verified observation:

```bash
python3 scripts/evidence-ledger.py append \
  /path/to/evidence/local-inventory.json \
  /path/to/evidence/ledger.jsonl
```

The selected evidence file must contain a valid `evidence-envelope-v1`
envelope with a non-empty `tenant_id`; `scripts/inventory-local.sh` creates
that envelope and accepts an optional tenant ID.

Verify the complete chain:

```bash
python3 scripts/evidence-ledger.py verify /path/to/evidence/ledger.jsonl
```

Local host inventory labels the evidence `local` by default; pass an explicit
tenant identifier as the second argument when the observation belongs to a
registered tenant. The local API can use the same file by setting
`A2Z_EVIDENCE_LEDGER_PATH` before startup. The parent directory must already
exist and the ledger file must have owner-only permissions.

The ledger is local evidence storage only. It does not authorize actions,
mint credentials, connect to customer systems, or replace a signed approval.
