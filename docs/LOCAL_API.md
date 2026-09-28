# Local Control-Plane API

The facade is loopback-only and serves the operator console at `/`. Without
`A2Z_DATABASE_URL`, application state remains in memory. The optional
PostgreSQL path is documented in [`DATABASE_AND_ANALYTICS.md`](./DATABASE_AND_ANALYTICS.md).
It persists tenants, identities, assets, authorization requests, offline plans,
verified approvals, integration metadata, asset graph nodes/edges, direct API
evidence events, change-workflow snapshots, transactional workflow evidence,
and analytics. Workflow state is reconstructed from tenant-scoped plan records
at startup. Without PostgreSQL, lifecycle state stays in memory; the file-backed
JSONL evidence adapter remains available:

```bash
PYTHONPATH=src python3 scripts/run-local-api.py
```

Available boundaries:

- `GET /healthz`
- `GET /readyz` — production gate for PostgreSQL connectivity, core schema, and forced tenant RLS; returns `503` in in-memory mode.
- `GET /v1/database/status`
- `GET /v1/analytics/overview?tenant_id=<uuid>`
- `GET /v1/integrations/catalog`
- `GET /v1/integrations/connections?tenant_id=<tenant>`
- `POST /v1/integrations/connections` (metadata-only draft; no endpoint probe)
- `POST /v1/integrations/connections/probe` (PostgreSQL-backed, allowlisted read-only REST/OpenAPI, MCP, or Redfish probe)
- `POST /v1/tenants`
- `POST /v1/identities`
- `POST /v1/assets`
- `POST /v1/authorization-requests`
- `POST /v1/plans`
- `POST /v1/approvals`
- `POST /v1/inventory/observe`
- `POST /v1/plan-evaluations`
- `POST /v1/agent-tool-calls/authorize`
- `POST /v1/workload-identity/evaluate`
- `POST /v1/sessions/open`
- `POST /v1/sessions/close`
- `POST /v1/break-glass/evaluate`
- `POST /v1/graph/nodes`, `/v1/graph/edges`, and `/v1/graph/query`
- `POST /v1/drift/evaluate`
- `POST /v1/verification/evaluate`
- `POST /v1/evidence/append`, `/v1/evidence/query`, and `/v1/evidence/verify`
- `POST /v1/change-workflows`
- `POST /v1/change-workflows/approve`, `/dispatch`, `/verify`, and `/rollback`

The authorization and change-workflow paths do not persist credentials, call
infrastructure provider APIs, bind publicly, execute plans, or authorize
cross-tenant references. Separate optional read-only integration routes can
fetch OpenRouter/vLLM model catalogs and list tools from explicitly configured
MCP Streamable HTTP servers; see [`LOCAL_INTEGRATIONS.md`](./LOCAL_INTEGRATIONS.md).
They do not run model completions or invoke MCP tools. Without PostgreSQL, the
in-memory evidence store can be replaced with the file-backed ledger by setting
`A2Z_EVIDENCE_LEDGER_PATH` to a file in an existing private directory.

Graph records are backed by tenant-scoped assets and graph_edges when
PostgreSQL is enabled; graph writes append evidence in the same database
transaction. Graph, drift, and verification routes do not connect to providers,
mint credentials, dispatch changes, or perform rollback. Cross-tenant graph
and receipt/state requests are rejected. Evidence is partitioned into
independent tenant hash chains; query and verification responses never return
another tenant's records.

Approval submission requires a signed Ed25519 record in `signed_record`.
The API invokes the configured repository verifier and binds the signature to
the registered request's tenant, target, action, environment, and capabilities.
The former caller-supplied `signature_verified` flag is not accepted as proof.
The approval scope includes the workflow plan identifier. The change workflow
accepts only verified approvals for its request, records each transition in
the tenant evidence chain, dispatches only through the simulation lifecycle,
and exposes rollback as an event record rather than a provider operation.
