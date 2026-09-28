# Local Live Integration Console

The local application now serves a functional console at `/` and a loopback
API. Integration credentials and destinations are supplied to the API process
through environment variables; they are never submitted by browser code or
returned by status endpoints.

## Start on macOS/Linux

From the project root:

```bash
PYTHONPATH=src python3 scripts/run-local-api.py --host 127.0.0.1 --port 8794
```

Open `http://127.0.0.1:8794/`. Verify the API separately with
`curl http://127.0.0.1:8794/healthz`. The server rejects non-loopback bind
addresses. Do not publish this development API to a LAN or the internet; it
does not include production user authentication.

## Configure a live provider

Restart the API with the relevant environment variables set. Avoid putting
secrets in shell history or source control; use a local secret manager or a
hidden prompt in the current shell and keep the variable scoped to this
process.

| Variable | Purpose |
|---|---|
| `A2Z_OPENROUTER_API_KEY` | Server-side credential for a read-only OpenRouter model-catalog request (`GET /api/v1/models`). No completion requests are made. |
| `A2Z_VLLM_BASE_URL` | Customer-hosted vLLM base URL; the app requests `<base>/v1/models`. HTTPS is required except loopback HTTP for local development. |
| `A2Z_VLLM_API_KEY` | Optional server-side bearer credential for a protected vLLM endpoint. |
| `A2Z_MCP_SERVERS_JSON` | JSON list of operator-configured Streamable HTTP MCP server IDs and URLs. |
| `A2Z_MCP_ALLOWED_HOSTS` | Comma-separated exact hostnames authorized for remote MCP connections. Loopback endpoints are allowed for local development. |
| `A2Z_MCP_TOKEN_<NAME>` | Optional bearer credential referenced by a server's `token_env`; secret values are not embedded in server JSON. |
| `A2Z_MCP_PROTOCOL_VERSION` | Pin the legacy initialize protocol when needed. Default `2026-07-28` first uses `server/discover`, then falls back to `2025-11-25` when the server does not implement discovery. |
| `A2Z_INTEGRATION_ALLOWED_HOSTS` | Administrator-owned comma-separated exact origins allowed for saved REST/OpenAPI, Redfish, and MCP probes. Host-only entries authorize HTTPS port 443; nonstandard ports require `host:port`. The saved connector host list is also required. |

Example MCP server configuration (no credentials included):

```json
[{"id":"internal-docs","url":"https://mcp.example.org/mcp"}]
```

The MCP probe follows the current stateless protocol with `server/discover`
and `tools/list`, falling back to the legacy initialize exchange when needed.
It does **not** invoke tools. Server URLs must be administrator
configuration, not request parameters; remote endpoints must use HTTPS and an
exact-host allowlist entry, and redirects are not followed. This first local
implementation supports Streamable HTTP, not stdio subprocesses or legacy SSE.

## API paths

- `GET /v1/integrations/status` — configured/not-configured metadata; no secrets.
- `GET /v1/integrations/openrouter/models` — live OpenRouter model catalog.
- `GET /v1/integrations/vllm/models` — live vLLM `/v1/models` catalog.
- `GET /v1/integrations/mcp/tools` — live MCP protocol discovery and tool manifest listing, with legacy handshake fallback.
- `GET /v1/integrations/prices/azure-retail` — bounded, unauthenticated Azure consumption-list-price lookup by service/region/SKU/currency; no database write and no estimate mutation.
- `GET /v1/integrations/connections?tenant_id=<tenant>` — saved tenant-scoped connections and last probe outcome.
- `POST /v1/integrations/connections` — save a connector draft; no network call.
- `POST /v1/integrations/connections/probe` — run a supported adapter's read-only probe and persist the run.
- `POST /v1/inventory/observe` — invoke a server-registered inventory connector by ID; with PostgreSQL configured, upsert the typed observations into `assets` and append their evidence in one transaction.

These are live reads, not mock results. The first saved per-connection adapter
set is:

- `rest_openapi`: GET the configured URL and report an OpenAPI title/version/
  path count or a compact JSON response-key summary.
- `redfish`: GET the DMTF service root (`/redfish/v1/` for an origin), then
  follow same-origin Systems and Chassis links and report member counts.
- `mcp_http`: perform discovery and `tools/list`; tools are never invoked.

Remote probes require HTTPS and both the connector's exact saved host and the
administrator-owned `A2Z_INTEGRATION_ALLOWED_HOSTS` host/port entry. Loopback HTTP is
allowed for local testing. Redirects are refused; requests have bounded time
and response size. A credential reference is resolved from the server
environment and sent only to the pinned host. Bearer tokens are supported for
REST and MCP; Redfish also supports HTTP Basic when its referenced environment
secret is `USERNAME:PASSWORD`. PostgreSQL stores run status and sanitized
diagnostics plus a tenant evidence event in a single transaction; raw remote
response bodies and secrets are not stored.

Pinned SSH is a separate live inventory adapter, not a saved-connection probe:
start `scripts/run-live-ssh-observer-api.py` with a private host registry, then
call `/v1/inventory/observe` with `connector_id: "ssh-readonly"`. The registry
pins tenant, lab/development/staging scope, alias, login, identity, known-hosts,
and the fixed Linux helper. The helper exposes only host summary, systemd health,
and VirtualBox inventory; it cannot accept arbitrary commands. The connector
validates the helper's typed, privacy-minimized output before inventory/evidence
persistence. See [`VIRTUALBOX_FIRST_DEMO.md`](./VIRTUALBOX_FIRST_DEMO.md).

Other selectable protocols (SNMP, Modbus, BACnet, OPC UA, MQTT, and custom)
remain metadata drafts and fail before network access. Provider-specific cloud,
IoT, and virtualization inventory/telemetry synchronization and all write paths
remain unimplemented. These probes validate a connection contract; they do not
claim a vendor is fully integrated. See
[`DATABASE_AND_ANALYTICS.md`](./DATABASE_AND_ANALYTICS.md) for PostgreSQL setup.

The Azure Retail Prices lookup is a separate public catalog read, not an Azure
tenant connector. It uses Microsoft's fixed endpoint and a bounded single-page
response, does not use credentials or follow pagination links, and never writes
price observations. Returned rates are retail list prices, not negotiated
discounts, taxes, support, or customer bills; quote and contract inputs must
remain separately sourced. It uses the documented
`2023-01-01-preview` API version; see the [official Azure Retail Prices REST API
reference](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices).

The sizing view can add a returned meter to a browser-local estimate draft.
Operators must enter billable units per month explicitly; monthly list cost is
`retailPrice × quantity_per_month` and annualized list cost is that amount × 12.
The CSV keeps the response retrieval timestamp, source URL, SKU, region,
effective date, currency, unit, and price type with each line. The draft is not
persisted, does not update a scenario or price book, and is not a quote or full
TCO; blank quantities remain unpriced. Discounts, taxes, support, egress,
commitments, taxes, and customer-specific agreements require separate evidence.

Google Cloud public pricing is available through the separate fixed-endpoint
Billing Catalog adapter at `/v1/integrations/prices/google-cloud-retail`. Set
`GOOGLE_CLOUD_BILLING_API_KEY` only in the server environment, restrict it to
the Cloud Billing Catalog API and preferably the server egress IP, then restart
the service. The key is never accepted from or returned to the browser. The
adapter reads one bounded page (up to 200 SKUs), reports truncation and does
not follow arbitrary next-page URLs. It exposes public catalog tiers; only a
single zero-threshold rate can enter the simple quantity estimator. This is
not account-specific contract pricing; the separate permissioned Google
Pricing API is not implemented. No observation is persisted and no cloud
resource API is called. See Google's [catalog API guide](https://docs.cloud.google.com/billing/v1/how-tos/catalog-api),
[SKU list API](https://docs.cloud.google.com/billing/docs/reference/rest/v1/services.skus/list),
and [account-specific pricing guidance](https://docs.cloud.google.com/billing/docs/how-to/get-pricing-information-api).

MCP version compatibility follows the [2026-07-28 protocol revision](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/docs/specification/2026-07-28), whose stateless flow uses per-request metadata and `server/discover`; legacy servers use the fallback initialize exchange.

## Workspace onboarding and evidence export

The browser-local Workspace setup stores only profile/objective preferences and
uses the selected profile to filter suggested workload blueprints. It does not
change tenant records or grant connector/tool authority. The integration catalog
is rendered with its declared adapter contract so metadata-only protocols remain
clearly “contract pending.” Credentials must be provided through the configured
server-side secret boundary, never pasted into the onboarding form.

Topology uses the existing tenant-scoped `/v1/graph` read model. The UI builds a
bounded, deterministic layered view (200 nodes / 400 edges) and uses
adjacency-list breadth-first traversal, O(V+E), for a two-hop context trace.
Edges describe recorded relationships only; they do not assert reachability,
authorization, or operational safety.

Workspace setup offers a local JSON due-diligence snapshot from read-only
overview, integration, graph, and evidence APIs. It includes a non-certification
disclaimer and never submits the file to a service. The downloaded file may
contain tenant-scoped resource and evidence metadata; inspect and redact it
before sharing. Synthetic/demo provenance remains explicit in the underlying
API responses.

The **Placement tradeoffs** command-center view compares on-premises/colocation
and cloud-subscription lifecycle economics, workload fit and decision gates.
It is a browser-local scenario tool: both cases require explicit cost entries,
evidence type/reference/date, shared currency, horizon, discount assumption
and useful-output volume. Blank categories do not silently become zero. It
shows nominal lifecycle total, discounted present value, monthly equivalent,
first-year cash and cost per useful unit, then labels any lower-cost case as
arithmetic only—not an architecture recommendation or authorization. The JSON
export remains in the browser; the comparison is neither sent to APIs nor
persisted. Cost inputs should cover facility/hardware refresh and operations
on-prem, and managed services, egress, support and commitment under-utilization
in cloud. Taxes, FX, inflation, financing, changing demand and unmodeled
downtime are identified exclusions. Use comparable workload scope, service
level, resiliency and price dates; public list prices are not negotiated rates.
See the [Google Cloud cost pillar](https://docs.cloud.google.com/architecture/framework/cost-optimization),
[Azure rate strategy](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/get-best-rates),
[AWS cloud financial management](https://docs.aws.amazon.com/solutions/cloud-financial-management-on-aws/),
and [FinOps unit economics](https://framework.finops.org/framework/capabilities/unit-economics/).
