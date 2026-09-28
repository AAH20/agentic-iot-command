# Agentic_IoT_Command PostgreSQL, synthetic data, integrations, and analytics

The `opsatlas` database schema name is retained as an internal compatibility
namespace during the product rebrand.

Sizing, priced takeoffs, lifecycle PV, actual-cost reconciliation and unit
economics are defined in [`COST_ESTIMATING_AND_UNIT_ECONOMICS.md`](COST_ESTIMATING_AND_UNIT_ECONOMICS.md).
For databases created before this extension, apply
[`../database/migrations/001_cost_intelligence.sql`](../database/migrations/001_cost_intelligence.sql)
and then [`../database/migrations/002_lifecycle_rollup_fix.sql`](../database/migrations/002_lifecycle_rollup_fix.sql)
and [`../database/migrations/003_estimate_price_link_validation.sql`](../database/migrations/003_estimate_price_link_validation.sql)
and [`../database/migrations/004_placement_comparison_snapshots.sql`](../database/migrations/004_placement_comparison_snapshots.sql)
once each as the database owner after reviewing the target DSN and taking a backup.
They are additive; the API reports the dedicated cost-schema error until they are applied.
`../database/demo_cost_seed.sql` is an optional synthetic-only addition for a demo tenant.

## Scope and honest runtime state

`database/schema.sql` is the portable PostgreSQL 14+ core. It uses standard
PostgreSQL UUID, `timestamptz`, `numeric`, arrays, JSONB, constraints, and RLS;
it does not require TimescaleDB or another extension. `opsatlas` is deliberately
not the browser's direct write API. The loopback Python API can use the optional
Psycopg pool for tenant, inventory, request/plan and verified-approval reads
and writes, integration metadata, analytics, graph assets/edges, and direct API
evidence events. Graph writes and their hash-chain evidence append share one DB
transaction. Change-workflow lifecycle state and the workflow service's own
evidence events are not fully migrated; use the database status badge and do
not treat this milestone as a production database cutover.

The local Mac has PostgreSQL 14.15 server/client tools and an existing cluster
at `/opt/homebrew/var/postgresql@14`. For this setup, that cluster was inspected
and snapshotted offline before startup; PostgreSQL completed crash recovery and
is currently running on loopback. It was started manually, not configured for
automatic login startup. Check status before starting it again, and do not run
both `pg_ctl` and Homebrew service startup against the same cluster:

```bash
pg_ctl -D /opt/homebrew/var/postgresql@14 status
pg_isready
```

If the cluster is stopped, start that existing cluster and create an empty
development database (the bootstrap refuses to reuse an existing DB):

```bash
pg_ctl -D /opt/homebrew/var/postgresql@14 -l /private/tmp/opsatlas-postgres.log start
cd "/Users/ahmedhassan/Downloads/2000 workflows/a2z-agentic-control-plane-handoff"
A2Z_DB_NAME=opsatlas_dev bash scripts/db-bootstrap-local.sh
```

The API remains in memory until the optional driver and a PostgreSQL connection
are configured. Install the pinned DB extras in the project's isolated virtual
environment. For the local socket, the connection URI contains no credential;
for hosted PostgreSQL, inject the DSN from a secret manager (never a shell
argument, source file, or browser field):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-db.txt
export A2Z_DATABASE_URL=postgresql:///opsatlas_dev
PYTHONPATH=src python3 scripts/run-local-api.py --host 127.0.0.1 --port 8787
```

Use a restricted application role in real deployments; the schema owner used
for local bootstrap is not a production API identity. For Supabase transaction
pooler URLs, the Psycopg pool disables automatic prepared statements and tenant
scope is set transaction-locally so it does not leak between pooled sessions.

## Empty production bootstrap vs demo reset

For a new production database, bootstrap a *new empty database* and do not run
the synthetic seed. The script never drops a database and refuses if its target
already exists. There is intentionally no production-reset command. Demo reset
is restricted to `opsatlas_demo`/`opsatlas_dev`, a local loopback connection,
and an exact acknowledgement token; it deletes only the `opsatlas-demo`
synthetic tenant, cascading its synthetic rows while preserving schema and
other tenants.

```bash
A2Z_DB_NAME=opsatlas_prod bash scripts/db-bootstrap-local.sh
A2Z_DB_NAME=opsatlas_demo bash scripts/db-bootstrap-local.sh
A2Z_DB_NAME=opsatlas_demo A2Z_ALLOW_SYNTHETIC_DATA=YES_SYNTHETIC_opsatlas_demo bash scripts/db-seed-demo.sh
A2Z_DB_NAME=opsatlas_demo A2Z_ALLOW_DEMO_RESET=RESET_opsatlas_demo bash scripts/db-reset-demo.sh
```

No script accepts `PGSERVICE`; bootstrap, seed, reset, and stress-test refuse
non-loopback `PGHOST`/`PGHOSTADDR` values. Never set an `opsatlas_*` demo name
for a hosted production connection.

## Relational domains

| Domain | Core tables | Grain / design notes |
|---|---|---|
| Organization and sites | `tenants`, `tenant_memberships`, `sites`, `facilities`, `racks` | Tenant-scoped facilities, power capacity, geospatial coordinates, explicit membership |
| Fleet and topology | `assets`, `asset_identifiers`, `graph_edges` | Stable external IDs, parent/rack relationships, indexed graph traversal in both directions |
| Integration control plane | `integration_connections`, `integration_capabilities`, `integration_runs` | Protocol/vendor/version, exact allowed host list, least-privilege scopes, status and latency; secret *references only* |
| IAM/PAM | `identities`, `role_bindings`, `privileged_sessions` | Time-bounded, scoped bindings and session audit; no password/private-key columns |
| Governance | `authorization_requests`, `change_plans`, `approvals`, `evidence_events` | Immutable plan digests, signed approval bytes and signer key ID, tenant partition keys, hash-chain fields |
| Agentic AI | `agents`, `model_endpoints`, `mcp_servers`, `mcp_tools` | Trust state and manifest digest; MCP tools discovered separately from authorized tools |
| Sensor fusion and energy | `sensor_definitions`, `sensor_readings`, `energy_readings` | Unit-aware definitions, event time plus ingest time, source run and quality flags, BRIN/time indexes |
| Predictive maintenance | `maintenance_rules`, `maintenance_work_orders`, `forecast_runs`, `forecast_points` | Versioned algorithms/parameters, confidence, horizon, input/model digest, uncertainty bounds and explanation |
| Continuous BI | `kpi_definitions`, `kpi_observations` | Versioned formula, sample count, status/freshness, dimension and lineage payload |
| Capacity and test evidence | `benchmark_runs` | Workload, concurrency, environment and measured result are separate from operational telemetry |

Composite tenant foreign keys prevent cross-tenant references. Tenant-owned
tables have RLS enabled and forced; local API transactions set
`opsatlas.tenant_id` transaction-locally, and missing scope returns no rows.
`database/supabase_read_rls.sql` replaces this local service policy with
Supabase Auth membership-based *read-only* policies. The browser must never
receive `service_role` or database credentials.

Graph nodes are the tenant's `assets`; edges live in `graph_edges`. Graph list
responses are capped at 10,000 assets and 20,000 edges until cursor pagination
is implemented. API evidence records use the existing `evidence_events` table:
the full canonical hash-chain record is stored in JSONB and appended under a
tenant-row lock. Legacy synthetic seed rows without `record_version` remain
visible as raw demo rows but are excluded from the verified API hash chain.

## Supabase mapping

Apply the core schema as a versioned SQL migration in a new Supabase project,
then apply `database/supabase_read_rls.sql`, create tenant memberships from a
trusted administrative path, and add `opsatlas` to the project's exposed Data
API schemas only if direct authenticated reads are actually needed. Keep direct
browser writes disabled; this control plane's API owns governed writes. Verify
grants and RLS for every table before exposing it. Demo membership UUIDs do not
correspond to a real Supabase Auth user. The schema uses no `auth` dependency
until the overlay, so it can also be hosted on ordinary PostgreSQL.

Supabase's current Data API exposure defaults changed during 2026. Do not rely
on automatic table exposure: explicitly configure exposed schemas and grants,
and retain RLS. Use direct connections for long-lived backends where available;
use the transaction pooler for bursty/serverless clients, with prepared
statements disabled. Consult the current [RLS guide](https://supabase.com/docs/guides/database/postgres/row-level-security),
[connection guide](https://supabase.com/docs/guides/database/connecting-to-postgres),
and [Data API security guide](https://supabase.com/docs/guides/api/securing-your-api)
at deployment time.

## UI integration workflow

1. Select/create a tenant in the rail.
2. Open **Integrations → Register a vendor/API/MCP endpoint**.
3. Choose a protocol, name the exact vendor/API family and version, enter its
   endpoint, list the exact hostname, and request only read scopes.
4. Enter a secret-manager/environment *reference name*, never the credential.
5. Save. The connection is a `draft`; it is not probed, trusted, or marked live.
6. Implement a protocol adapter behind the typed connector contract; add
   allowlisted destination policy, TLS/identity checks, bounded timeouts and
   response sizes, vendor contract tests, a read-only integration test, and
   evidence/freshness reporting. Only a passing real probe may promote it to
   `healthy`. A catalog entry is not an adapter.

Available protocol slots include REST/OpenAPI, MCP Streamable HTTP, DMTF
Redfish, SNMPv3, Modbus TCP, BACnet/IP, OPC UA, MQTT, pinned SSH read-only, and
custom adapters. Actual cloud, IoT, BMC, hypervisor, BMS/EPMS/DCIM vendor
connectors still require separate implementations and authorized endpoints.
Do not configure private credentials or connect OT safety/control systems in
this local demo.

## KPI and predictive analytics contract

The persistent analytics endpoint is `GET /v1/analytics/overview?tenant_id=…`.
The UI's cross-tab KPI ribbon and Energy & Facilities view read database-backed
asset/request/connector/maintenance counts, 24-hour energy rollups, sensor
freshness, and latest KPI snapshots with sample count and lineage. Numeric
energy is stored as exact `numeric`; high-volume sensor numeric values use
`numeric` as well. Every observation carries quality and source-run lineage.

Initial metric families: fleet coverage/freshness, incident and request flow,
approval latency, connector success/latency/freshness, energy kWh and mean/peak
kW, PUE where both facility and IT energy are available, energy/carbon per
compute unit when workload attribution exists, sensor quality, maintenance
backlog/MTTR, forecast error, and capacity headroom. A KPI is `partial` or
`stale` rather than silently imputed when required inputs are absent.

`maintenance_rules` stores algorithm versions and thresholds. The demo seed's
rolling baseline and forecast rows are explicitly synthetic and advisory; they
are not a trained failure model or real prediction. A production model needs
time-ordered validation, a holdout period, calibration, false-negative cost,
drift monitoring, and human review before creating work orders. It never
automatically actuates equipment.

## Scaling and stress-test protocol

- Sensor/event tables are append-heavy. Start with tenant/time composite B-tree
  indexes plus BRIN on event time; batch inserts and retain source timestamps.
  At measured scale, partition readings monthly by event time, add retention and
  cold-storage policy, and run `ANALYZE`/vacuum. Partitioning is intentionally
  a later migration so the baseline stays portable to Supabase Postgres.
- Keep transactions short; use the bounded Psycopg pool (default max 8), and
  put PgBouncer/Supavisor in front of bursty horizontally scaled services.
  Use keyset/cursor pagination for long event lists; never fetch all telemetry
  into a browser table.
- Run `EXPLAIN (ANALYZE, BUFFERS)` on representative tenant/time-window queries
  using a demo dataset. Check query plans, index selectivity, connection waits,
  replication lag, autovacuum, pool saturation, and API p50/p95/p99.
- The guarded pgbench scenario is read-only and demo-only: it runs indexed
  tenant-scoped sensor/energy/assets queries for 5–120 seconds with 1–16
  clients, reports TPS and captures per-transaction p50/p95/p99 latency logs.
  It does not simulate write ingestion or cloud/vendor request quotas.

```bash
A2Z_DB_NAME=opsatlas_demo A2Z_ALLOW_STRESS_TEST=YES_STRESS_opsatlas_demo \
  A2Z_STRESS_SECONDS=30 A2Z_STRESS_CLIENTS=8 bash scripts/db-stress-test.sh
```

Establish a baseline at 1/2/4/8/16 clients, compare identical data and hardware,
then add separate batch-ingest, API end-to-end, outage/reconnect, tenant
isolation, and forecast-pipeline tests before making a capacity claim. Do not
run stress workloads against production.
