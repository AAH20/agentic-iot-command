from __future__ import annotations

import json
import hashlib
import os
import re
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from .models import AuthorizationRequest
from .registry import ApprovalRecord, LocalControlPlaneStore
from .connectors import ConnectorRegistry, ReadOnlyConnector
from .plan import OfflinePlanService
from .agents import AgentRegistry, AgentToolGateway, ToolCall
from .iam import BreakGlassService, SessionGateway, WorkloadIdentityBroker, WorkloadIdentityRequest
from .graph import GraphEdge, GraphNode, RelationshipGraph
from .drift import DriftDetector
from .lifecycle import ExecutionReceipt
from .verification import PostChangeVerifier
from .evidence import EvidenceLedger
from .approval import ApprovalVerifier, Ed25519ApprovalVerifier
from .controlled_changes import ControlledChangeService
from .live_integrations import LiveIntegrations
from .database import PostgresRepository


def validate_placement_snapshot(body: dict[str, Any]) -> tuple[str, str, str, str]:
    """Validate a bounded draft snapshot and produce its canonical integrity hash."""
    name, payload = body.get("name"), body.get("payload")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
        raise ValueError("name must contain 1-120 characters")
    if not isinstance(payload, dict) or payload.get("schema_version") != "placement-tco-comparison.v1":
        raise ValueError("unsupported placement comparison payload")
    assumptions, sources, results = payload.get("assumptions"), payload.get("sources"), payload.get("results")
    if not isinstance(assumptions, dict) or not isinstance(sources, dict) or not isinstance(results, dict):
        raise ValueError("comparison assumptions, sources, and results are required")
    if not re.fullmatch(r"[A-Za-z]{3}", str(assumptions.get("currency", ""))):
        raise ValueError("comparison currency must be a 3-letter code")
    horizon = assumptions.get("horizon_months")
    if not isinstance(horizon, int) or isinstance(horizon, bool) or not 1 <= horizon <= 120:
        raise ValueError("comparison horizon must be 1-120 months")
    from datetime import date
    for side in ("onprem", "cloud"):
        source = sources.get(side)
        if not isinstance(source, dict) or not all(
            isinstance(source.get(key), str) and source[key].strip()
            for key in ("type", "reference", "observed_on")
        ):
            raise ValueError(f"{side} source type, reference, and observation date are required")
        try:
            date.fromisoformat(source["observed_on"])
        except ValueError:
            raise ValueError(f"{side} observation date must be YYYY-MM-DD") from None
        if not isinstance(results.get(side), dict):
            raise ValueError(f"{side} calculated result is required")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("comparison snapshot exceeds 64 KiB")
    return name.strip(), encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), payload["schema_version"]


class LocalControlPlaneApi:
    """Loopback-only HTTP facade for the Phase 1 local bounded context."""

    def __init__(self, store: LocalControlPlaneStore | None = None, approval_verifier: ApprovalVerifier | None = None) -> None:
        self.store = store or LocalControlPlaneStore()
        self.connectors = ConnectorRegistry()
        self.plan_service = OfflinePlanService()
        self.agent_registry = AgentRegistry()
        self.tool_gateway = AgentToolGateway(self.agent_registry)
        self.workload_identity = WorkloadIdentityBroker()
        self.sessions = SessionGateway()
        self.break_glass = BreakGlassService()
        self.graph = RelationshipGraph()
        self.drift_detector = DriftDetector()
        self.verifier = PostChangeVerifier(self.drift_detector)
        self.evidence = EvidenceLedger(os.environ.get("A2Z_EVIDENCE_LEDGER_PATH") or None)
        self.approval_verifier = approval_verifier or Ed25519ApprovalVerifier()
        self.change_workflows = ControlledChangeService(self.store, self.evidence, verifier=self.verifier)
        self.live_integrations = LiveIntegrations()
        self.database: PostgresRepository | None = None
        self.database_error: str | None = None
        self.integration_connections: dict[str, list[dict[str, Any]]] = {}
        dsn = os.environ.get("A2Z_DATABASE_URL")
        if dsn:
            try:
                self.database = PostgresRepository(dsn)
            except Exception as exc:
                self.database_error = "database_driver_missing" if isinstance(exc, RuntimeError) else "database_unavailable"
        if self.database:
            self.change_workflows.repository = self.database
            try:
                for tenant in self.database.tenants():
                    self.store.tenants.setdefault(tenant["tenant_id"], {"tenant_id": tenant["tenant_id"], "name": tenant["name"], "status": tenant["status"]})
                    inventory = self.database.inventory(tenant["tenant_id"])
                    self.store.identities.update({row["identity_id"]: row for row in inventory["identities"]})
                    self.store.assets.update({row["asset_id"]: row for row in inventory["assets"]})
                    for row in self.database.requests(tenant["tenant_id"]):
                        request = AuthorizationRequest(
                            request_id=UUID(row["request_id"]), actor_id=row["actor_id"], action=row["action"],
                            target=row["target"], environment=row["environment"], capabilities=tuple(row["capabilities"]),
                            mode=row["mode"], reason=row["reason"], tenant_id=row["tenant_id"],
                        )
                        self.store.requests[row["request_id"]] = request
                    for row in self.database.plans(tenant["tenant_id"]):
                        self.store.plans[row["plan_id"]] = {**row, **(row.get("plan") if isinstance(row.get("plan"), dict) else {})}
                    persisted_workflows = self.database.persisted_change_workflows(tenant["tenant_id"])
                    self.change_workflows.restore_persisted(
                        tenant["tenant_id"], [row["plan"] for row in persisted_workflows]
                    )
                    for row in self.database.approvals(tenant["tenant_id"]):
                        if row.get("revoked_at") is None:
                            self.store.approvals[row["approval_id"]] = ApprovalRecord(
                                approval_id=row["approval_id"], request_id=row["request_id"],
                                approver_id=row["approver_id"], tenant_id=tenant["tenant_id"],
                                signature_verified=True, expires_at=str(row["expires_at"]), plan_id=row["plan_id"],
                            )
            except Exception:
                self.database_error = "schema_missing_or_unavailable"

    def register_connector(self, connector: ReadOnlyConnector) -> None:
        self.connectors.register(connector)

    def register_agent_tool(self, agent: object) -> None:
        self.agent_registry.register_agent(agent)  # type: ignore[arg-type]

    def register_tool(self, tool: object) -> None:
        self.agent_registry.register_tool(tool)  # type: ignore[arg-type]

    def dispatch(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        body = body or {}
        parsed_path = urlsplit(path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        try:
            if method == "GET" and path == "/healthz":
                return 200, self.store.health()
            if method == "GET" and path == "/readyz":
                if not os.environ.get("A2Z_DATABASE_URL"):
                    return 503, {"ready": False, "checks": {"database": "not_configured", "schema": "unchecked", "tenant_rls": "unchecked"}, "execution_permitted": False}
                if self.database is None:
                    return 503, {"ready": False, "checks": {"database": self.database_error or "unavailable", "schema": "unchecked", "tenant_rls": "unchecked"}, "execution_permitted": False}
                try:
                    result = self.database.readiness()
                    return (200 if result["ready"] else 503), result
                except Exception:
                    return 503, {"ready": False, "checks": {"database": "unavailable", "schema": "unchecked", "tenant_rls": "unchecked"}, "execution_permitted": False}
            if method == "GET" and path == "/v1/overview":
                return 200, {
                    "health": self.store.health(),
                    "tenants": list(self.store.tenants.values()),
                    "recent_requests": [self._request_summary(item) for item in list(self.store.requests.values())[-20:][::-1]],
                    "recent_plans": list(self.store.plans.values())[-20:][::-1],
                    "active_connectors": [self._manifest_summary(item) for item in self.connectors.manifests()],
                    "execution_permitted": False,
                }
            if method == "GET" and path == "/v1/database/status":
                if not os.environ.get("A2Z_DATABASE_URL"):
                    return 200, {"status": "not_configured", "persistence": "in_memory", "execution_permitted": False}
                if self.database is None:
                    return 503, {"status": self.database_error or "unavailable", "persistence": "in_memory", "execution_permitted": False}
                try:
                    return 200, self.database.status()
                except Exception:
                    return 503, {"status": "database_unavailable", "execution_permitted": False}
            if method == "GET" and path == "/v1/analytics/overview":
                tenant_id = self._query_value(query, "tenant_id")
                include_synthetic_demo = query.get("demo") == ["synthetic"]
                if self.database is None:
                    return 503, {"error": self.database_error or "database_not_configured", "execution_permitted": False}
                try:
                    return 200, self.database.analytics_overview(tenant_id, include_synthetic_demo)
                except Exception:
                    return 503, {"error": "database_unavailable_or_schema_missing", "execution_permitted": False}
            if method == "GET" and path == "/v1/analytics/costs":
                tenant_id = self._query_value(query, "tenant_id")
                include_synthetic_demo = query.get("demo") == ["synthetic"]
                if self.database is None:
                    return 503, {"error": self.database_error or "database_not_configured", "execution_permitted": False}
                try:
                    return 200, self.database.lifecycle_cost_overview(tenant_id, include_synthetic_demo)
                except Exception:
                    return 503, {"error": "cost_schema_missing_or_database_unavailable", "execution_permitted": False}
            if method == "GET" and path == "/v1/placement/scenarios":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                if self.database is None:
                    return 503, {"error": "placement_snapshot_database_required", "execution_permitted": False}
                try:
                    return 200, {"tenant_id": tenant_id, "scenarios": self.database.placement_snapshots(tenant_id),
                                 "status": "draft_snapshots", "execution_permitted": False}
                except Exception:
                    return 503, {"error": "placement_snapshot_schema_missing_or_database_unavailable", "execution_permitted": False}
            if method == "GET" and path == "/v1/tenants":
                if self.database:
                    try:
                        return 200, {"tenants": self.database.tenants()}
                    except Exception:
                        return 503, {"error": "database_schema_missing_or_unavailable"}
                return 200, {"tenants": list(self.store.tenants.values())}
            if method == "GET" and path == "/v1/inventory":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                if self.database:
                    try:
                        return 200, {"tenant_id": tenant_id, **self.database.inventory(tenant_id)}
                    except Exception:
                        return 503, {"error": "database_schema_missing_or_unavailable"}
                return 200, {"tenant_id": tenant_id,
                    "identities": [x for x in self.store.identities.values() if x["tenant_id"] == tenant_id],
                    "assets": [x for x in self.store.assets.values() if x["tenant_id"] == tenant_id]}
            if method == "GET" and path == "/v1/requests":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                if self.database:
                    try:
                        return 200, {"tenant_id": tenant_id, "requests": self.database.requests(tenant_id)}
                    except Exception:
                        return 503, {"error": "database_schema_missing_or_unavailable"}
                return 200, {"tenant_id": tenant_id, "requests": [self._request_summary(x) for x in self.store.requests.values() if x.tenant_id == tenant_id]}
            if method == "GET" and path == "/v1/plans":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                if self.database:
                    try:
                        return 200, {"tenant_id": tenant_id, "plans": self.database.plans(tenant_id)}
                    except Exception:
                        return 503, {"error": "database_schema_missing_or_unavailable"}
                ids = {str(x.request_id) for x in self.store.requests.values() if x.tenant_id == tenant_id}
                return 200, {"tenant_id": tenant_id, "plans": [x for x in self.store.plans.values() if x.get("request_id") in ids]}
            if method == "GET" and path == "/v1/approvals":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                if self.database:
                    try:
                        return 200, {"tenant_id": tenant_id, "approvals": self.database.approvals(tenant_id)}
                    except Exception:
                        return 503, {"error": "database_schema_missing_or_unavailable"}
                return 200, {"tenant_id": tenant_id, "approvals": [
                    {"approval_id": x.approval_id, "request_id": x.request_id, "approver_id": x.approver_id, "expires_at": x.expires_at, "plan_id": x.plan_id}
                    for x in self.store.approvals.values() if x.tenant_id == tenant_id]}
            if method == "GET" and path == "/v1/graph":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                graph = self.database.graph_for_tenant(tenant_id) if self.database else self.graph.list_for_tenant(tenant_id)
                return 200, {"tenant_id": tenant_id, **graph, "execution_permitted": False,
                             "persistence": "postgres" if self.database else "in_memory"}
            if method == "GET" and path == "/v1/integrations/status":
                return 200, self.live_integrations.status()
            if method == "GET" and path == "/v1/integrations/catalog":
                return 200, {"protocols": [
                    {"id": "rest_openapi", "name": "REST / OpenAPI", "adapter": "read_only_http_probe"},
                    {"id": "mcp_http", "name": "MCP Streamable HTTP", "adapter": "per_connection_discovery_and_tools_list"},
                    {"id": "redfish", "name": "DMTF Redfish", "adapter": "read_only_service_root_probe"},
                    {"id": "snmp", "name": "SNMPv3", "adapter": "contract_pending"},
                    {"id": "modbus_tcp", "name": "Modbus TCP", "adapter": "contract_pending"},
                    {"id": "bacnet_ip", "name": "BACnet/IP", "adapter": "contract_pending"},
                    {"id": "opcua", "name": "OPC UA", "adapter": "contract_pending"},
                    {"id": "mqtt", "name": "MQTT", "adapter": "contract_pending"},
                    {"id": "ssh_readonly", "name": "Pinned SSH read-only", "adapter": "pinned_host_registry_inventory_observer"},
                    {"id": "custom", "name": "Custom vendor adapter", "adapter": "contract_pending"},
                ], "execution_permitted": False}
            if method == "GET" and path == "/v1/integrations/connections":
                tenant_id = self._query_value(query, "tenant_id")
                self.store.assert_tenant(tenant_id)
                try:
                    items = self.database.integration_connections(tenant_id) if self.database else self.integration_connections.get(tenant_id, [])
                except Exception:
                    return 503, {"error": "database_unavailable_or_schema_missing", "execution_permitted": False}
                return 200, {"tenant_id": tenant_id, "connections": items,
                    "persistence": "postgres" if self.database else "in_memory", "execution_permitted": False}
            if method == "GET" and path == "/v1/integrations/openrouter/models":
                return 200, self.live_integrations.models("openrouter")
            if method == "GET" and path == "/v1/integrations/vllm/models":
                return 200, self.live_integrations.models("vllm")
            if method == "GET" and path == "/v1/integrations/mcp/tools":
                return 200, self.live_integrations.mcp_tools()
            if method == "GET" and path == "/v1/integrations/prices/azure-retail":
                def optional_query_value(key: str, default: str) -> str:
                    values = query.get(key, [default])
                    if len(values) != 1:
                        raise ValueError(f"{key} query parameter may be specified only once")
                    return values[0]
                return 200, self.live_integrations.azure_retail_prices(
                    service_name=optional_query_value("service_name", "Virtual Machines"),
                    region=optional_query_value("region", ""),
                    sku=optional_query_value("sku", ""),
                    currency=optional_query_value("currency", "USD"),
                )
            if method == "GET" and path == "/v1/integrations/prices/google-cloud-retail":
                def optional_google_query_value(key: str, default: str) -> str:
                    values = query.get(key, [default])
                    if len(values) != 1:
                        raise ValueError(f"{key} query parameter may be specified only once")
                    return values[0]
                return 200, self.live_integrations.google_cloud_retail_prices(
                    service_name=optional_google_query_value("service_name", "Compute Engine"),
                    region=optional_google_query_value("region", ""),
                    sku_query=optional_google_query_value("sku_query", ""),
                    currency=optional_google_query_value("currency", "USD"),
                )
            if method == "POST" and path == "/v1/tenants":
                if self.database:
                    slug = str(body.get("tenant_id", ""))
                    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", slug):
                        raise ValueError("tenant slug must be 2-63 lowercase letters, digits, or hyphens")
                    try:
                        row = self.database.create_tenant(slug, str(body.get("name", "")))
                        self.store.create_tenant(row["tenant_id"], row["name"])
                        return 201, row
                    except Exception as exc:
                        raise ConnectionError("tenant could not be created in PostgreSQL") from exc
                return 201, self.store.create_tenant(body.get("tenant_id", ""), body.get("name", ""))
            if method == "POST" and path == "/v1/placement/scenarios":
                tenant_id = str(body.get("tenant_id", ""))
                self.store.assert_tenant(tenant_id)
                name, payload, digest, schema_version = validate_placement_snapshot(body)
                if self.database is None:
                    return 503, {"error": "placement_snapshot_database_required", "execution_permitted": False}
                try:
                    scenario = self.database.save_placement_snapshot(
                        tenant_id, name=name, payload=payload, payload_sha256=digest,
                        schema_version=schema_version,
                    )
                except Exception:
                    return 503, {"error": "placement_snapshot_schema_missing_or_database_unavailable", "execution_permitted": False}
                return 201, {"tenant_id": tenant_id, "scenario": scenario, "status": "draft_snapshot",
                             "execution_permitted": False}
            if method == "POST" and path == "/v1/integrations/connections":
                return 201, self._register_integration(body)
            if method == "POST" and path == "/v1/integrations/connections/probe":
                tenant_id = str(body.get("tenant_id", ""))
                self.store.assert_tenant(tenant_id)
                if self.database is None:
                    return 503, {"error": "database_required_for_saved_connector_probe", "execution_permitted": False}
                try:
                    connection_id = str(UUID(str(body.get("connection_id", ""))))
                    connection = self.database.integration_connection(tenant_id, connection_id)
                except KeyError as exc:
                    return 404, {"error": str(exc).strip("'\""), "execution_permitted": False}
                if connection["access_mode"] != "read_only" or connection["status"] == "disabled":
                    return 403, {"error": "connector is not enabled for read-only probes", "execution_permitted": False}
                try:
                    result = self.live_integrations.probe_connection(connection)
                    run = self.database.record_integration_probe(
                        tenant_id=tenant_id, connection_id=connection_id, result=result,
                    )
                    return 200, {**result, "connection_id": connection_id, "run": run}
                except (ValueError, PermissionError, ConnectionError) as exc:
                    error_code = "host_not_allowlisted" if isinstance(exc, PermissionError) else "probe_rejected" if isinstance(exc, ValueError) else "remote_unavailable"
                    run = self.database.record_integration_probe(
                        tenant_id=tenant_id, connection_id=connection_id, result=None, error_code=error_code,
                    )
                    return 200, {"connection_id": connection_id, "outcome": "failed", "error": str(exc),
                                 "run": run, "read_only": True, "execution_permitted": False}
            if method == "POST" and path == "/v1/identities":
                if self.database:
                    self.store.assert_tenant(body.get("tenant_id", ""))
                    try:
                        row = self.database.add_identity(body["tenant_id"], body.get("identity_id", ""), body.get("kind", ""))
                    except Exception as exc:
                        raise ConnectionError("identity could not be persisted") from exc
                    self.store.identities[row["identity_id"]] = {**row}
                    return 201, row
                return 201, self.store.register_identity(body.get("identity_id", ""), body.get("tenant_id", ""), body.get("kind", ""))
            if method == "POST" and path == "/v1/assets":
                if self.database:
                    self.store.assert_tenant(body.get("tenant_id", ""))
                    try:
                        row = self.database.add_asset(body["tenant_id"], body.get("asset_id", ""), body.get("kind", ""), body.get("environment", ""))
                    except Exception as exc:
                        raise ConnectionError("asset could not be persisted") from exc
                    self.store.assets[row["asset_id"]] = {**row}
                    return 201, row
                return 201, self.store.register_asset(body.get("asset_id", ""), body.get("tenant_id", ""), body.get("kind", ""), body.get("environment", ""))
            if method == "POST" and path == "/v1/authorization-requests":
                request = self._request_from_json(body)
                result = self.store.create_request(request)
                if self.database:
                    try:
                        self.database.add_request(request, result["decision"])
                    except Exception as exc:
                        raise ConnectionError("authorization request could not be persisted") from exc
                return 201, result
            if method == "POST" and path == "/v1/plans":
                plan = self.store.create_plan(body.get("request_id", ""))
                request = self.store.requests[plan["request_id"]]
                if self.database:
                    try:
                        self.database.add_plan(request.tenant_id, plan)
                    except Exception as exc:
                        raise ConnectionError("offline plan could not be persisted") from exc
                return 201, plan
            if method == "POST" and path == "/v1/approvals":
                signed_record = body.get("signed_record")
                if not isinstance(signed_record, dict):
                    raise ValueError("signed_record is required and must be an object")
                approval_payload = signed_record.get("approval", {}) if isinstance(signed_record, dict) else {}
                request_id = str(approval_payload.get("request_id", ""))
                request = self.store.requests.get(request_id)
                if request is None:
                    raise KeyError("authorization request not found")
                expected_scope = self.change_workflows.approval_scope_for_request(UUID(request_id))
                verified = self.approval_verifier.verify(signed_record, expected_scope=expected_scope)
                record = ApprovalRecord(
                    approval_id=verified["approval_id"],
                    request_id=verified["request_id"],
                    approver_id=verified["approver_id"],
                    tenant_id=verified["scope"]["tenant_id"],
                    signature_verified=True,
                    expires_at=verified["expires_at"],
                    plan_id=verified["scope"]["plan_id"],
                )
                if self.database:
                    try:
                        self.database.add_verified_approval(signed_record, verified)
                    except Exception as exc:
                        raise ConnectionError("verified approval could not be persisted") from exc
                return 201, self.store.record_approval(record)
            if method == "POST" and path == "/v1/change-workflows":
                request = self._request_from_json(body)
                if self.database:
                    result = self.store.create_request(request)
                    try:
                        self.database.add_request(request, result["decision"])
                    except Exception as exc:
                        raise ConnectionError("change workflow request could not be persisted") from exc
                return 201, self.change_workflows.start(request)
            if method == "POST" and path == "/v1/change-workflows/approve":
                return 200, self.change_workflows.approve(
                    workflow_id=UUID(str(body["workflow_id"])),
                    tenant_id=body["tenant_id"],
                    approval_id=body["approval_id"],
                )
            if method == "POST" and path == "/v1/change-workflows/dispatch":
                return 200, self.change_workflows.dispatch(
                    workflow_id=UUID(str(body["workflow_id"])), tenant_id=body["tenant_id"]
                )
            if method == "POST" and path == "/v1/change-workflows/verify":
                return 200, self.change_workflows.verify(
                    workflow_id=UUID(str(body["workflow_id"])),
                    tenant_id=body["tenant_id"],
                    expected_state=body["expected_state"],
                    observed_state=body["observed_state"],
                )
            if method == "POST" and path == "/v1/change-workflows/rollback":
                return 200, self.change_workflows.rollback(
                    workflow_id=UUID(str(body["workflow_id"])), tenant_id=body["tenant_id"]
                )
            if method == "POST" and path == "/v1/inventory/observe":
                self.store.assert_asset_scope(body["tenant_id"], body["target"], body["environment"])
                observations = self.connectors.observe(
                    body["connector_id"],
                    tenant_id=body["tenant_id"],
                    target=body["target"],
                    environment=body["environment"],
                )
                serialized = [observation.as_dict() for observation in observations]
                if self.database:
                    try:
                        assets = self.database.persist_inventory_observations(body["tenant_id"], serialized)
                    except Exception as exc:
                        raise ConnectionError("inventory observations could not be committed") from exc
                    persistence = "postgres"
                    self.store.assets.update({asset["asset_id"]: asset for asset in assets})
                else:
                    self._record_evidence(
                        tenant_id=body["tenant_id"],
                        event_type="inventory.observed",
                        collector="local-control-plane-api/0.1",
                        payload={"tenant_id": body["tenant_id"], "target": body["target"], "observations": serialized},
                    )
                    persistence = "in_memory"
                    for item in serialized:
                        self.store.assets[item["resource_id"]] = {
                            "asset_id": item["resource_id"], "tenant_id": item["tenant_id"],
                            "kind": item["resource_type"], "environment": item["environment"],
                            "status": "active", "observed_at": item["observed_at"],
                        }
                return 200, {"observations": serialized, "inventory_persistence": persistence}
            if method == "POST" and path == "/v1/plan-evaluations":
                return 200, self.plan_service.evaluate(body["artifact"]).as_dict()
            if method == "POST" and path == "/v1/agent-tool-calls/authorize":
                call = ToolCall(
                    call_id=UUID(str(body["call_id"])),
                    agent_id=body["agent_id"],
                    tenant_id=body["tenant_id"],
                    tool_id=body["tool_id"],
                    target=body["target"],
                    mode=body["mode"],
                    capability=body["capability"],
                    arguments=body.get("arguments", {}),
                    approval_ids=tuple(body.get("approval_ids", [])),
                )
                decision = self.tool_gateway.authorize(call)
                return 200, {
                    "call_id": str(decision.call_id),
                    "decision": decision.decision,
                    "reason_codes": list(decision.reason_codes),
                    "execution_permitted": decision.execution_permitted,
                }
            if method == "POST" and path == "/v1/workload-identity/evaluate":
                decision = self.workload_identity.evaluate(
                    WorkloadIdentityRequest(
                        request_id=UUID(str(body["request_id"])),
                        agent_id=body["agent_id"],
                        tenant_id=body["tenant_id"],
                        target=body["target"],
                        capabilities=tuple(body["capabilities"]),
                        environment=body["environment"],
                        expires_in_seconds=int(body["expires_in_seconds"]),
                    )
                )
                return 200, {"request_id": str(decision.request_id), "decision": decision.decision, "reason_codes": list(decision.reason_codes), "credential_issued": decision.credential_issued}
            if method == "POST" and path == "/v1/sessions/open":
                return 201, self.sessions.open(
                    tenant_id=body["tenant_id"], identity_id=body["identity_id"], target=body["target"], approved=bool(body.get("approved", False))
                ).as_dict()
            if method == "POST" and path == "/v1/sessions/close":
                return 200, self.sessions.close(session_id=UUID(str(body["session_id"])), tenant_id=body["tenant_id"]).as_dict()
            if method == "POST" and path == "/v1/break-glass/evaluate":
                decision = self.break_glass.evaluate(
                    request_id=UUID(str(body["request_id"])), tenant_id=body["tenant_id"], requester_id=body["requester_id"], target=body["target"], reason=body["reason"], approver_ids=tuple(body["approver_ids"]), expires_in_seconds=int(body["expires_in_seconds"]), environment=body["environment"]
                )
                return 200, {"request_id": str(decision.request_id), "decision": decision.decision, "reason_codes": list(decision.reason_codes), "expires_at": decision.expires_at, "post_review_required": decision.post_review_required, "credential_issued": decision.credential_issued}
            if method == "POST" and path == "/v1/graph/nodes":
                self.store.assert_tenant(body["tenant_id"])
                node = GraphNode(node_id=body["node_id"], tenant_id=body["tenant_id"], kind=body["kind"], attributes=body.get("attributes", {}))
                if self.database:
                    return 201, self.database.add_graph_node(node)
                node = self.graph.add_node(node)
                self._record_evidence(tenant_id=node.tenant_id, event_type="graph.node.added", collector="local-control-plane-api/0.1", payload=node.as_dict() | {"tenant_id": node.tenant_id})
                return 201, node.as_dict()
            if method == "POST" and path == "/v1/graph/edges":
                self.store.assert_tenant(body["tenant_id"])
                edge = GraphEdge(edge_id=UUID(str(body.get("edge_id", uuid4()))), tenant_id=body["tenant_id"],
                                 source_id=body["source_id"], target_id=body["target_id"], relation=body["relation"],
                                 attributes=body.get("attributes", {}))
                if self.database:
                    if not edge.relation.strip() or not isinstance(edge.attributes, dict):
                        raise ValueError("graph edge relation and attributes are required")
                    return 201, self.database.add_graph_edge(edge)
                edge = self.graph.add_edge(edge)
                self._record_evidence(tenant_id=edge.tenant_id, event_type="graph.edge.added", collector="local-control-plane-api/0.1", payload=edge.as_dict() | {"tenant_id": edge.tenant_id})
                return 201, edge.as_dict()
            if method == "POST" and path == "/v1/graph/query":
                self.store.assert_tenant(body["tenant_id"])
                graph = self.graph
                if self.database:
                    stored = self.database.graph_for_tenant(body["tenant_id"])
                    graph = RelationshipGraph()
                    for item in stored["nodes"]:
                        graph.add_node(GraphNode(**item))
                    for item in stored["edges"]:
                        graph.add_edge(GraphEdge(**{**item, "edge_id": UUID(item["edge_id"])}))
                return 200, graph.query(
                    tenant_id=body["tenant_id"],
                    root_id=body["root_id"],
                    depth=int(body.get("depth", 1)),
                    direction=body.get("direction", "both"),
                ).as_dict()
            if method == "POST" and path == "/v1/drift/evaluate":
                self.store.assert_tenant(body["tenant_id"])
                drift = self.drift_detector.compare(
                    tenant_id=body["tenant_id"],
                    resource_id=body["resource_id"],
                    desired=body["desired"],
                    observed=body["observed"],
                )
                self._record_evidence(tenant_id=drift.tenant_id, event_type="drift.evaluated", collector="local-control-plane-api/0.1", payload=drift.as_dict() | {"tenant_id": drift.tenant_id})
                return 200, drift.as_dict()
            if method == "POST" and path == "/v1/verification/evaluate":
                self.store.assert_tenant(body["tenant_id"])
                receipt_body = body["receipt"]
                receipt = ExecutionReceipt(
                    receipt_id=UUID(str(receipt_body["receipt_id"])),
                    plan_id=UUID(str(receipt_body["plan_id"])),
                    runner_id=receipt_body["runner_id"],
                    simulation=bool(receipt_body.get("simulation", True)),
                    credentials_issued=bool(receipt_body.get("credentials_issued", False)),
                    network_calls=int(receipt_body.get("network_calls", 0)),
                    status=receipt_body.get("status", "dispatched"),
                    tenant_id=receipt_body.get("tenant_id", ""),
                    resource_id=receipt_body.get("resource_id", ""),
                )
                report = self.verifier.verify(
                    receipt=receipt,
                    tenant_id=body["tenant_id"],
                    resource_id=body["resource_id"],
                    expected_state=body["expected_state"],
                    observed_state=body["observed_state"],
                )
                self._record_evidence(tenant_id=report.tenant_id, event_type="verification.completed", collector="local-control-plane-api/0.1", payload=report.as_dict() | {"tenant_id": report.tenant_id})
                return 200, report.as_dict()
            if method == "POST" and path == "/v1/evidence/append":
                self.store.assert_tenant(body["tenant_id"])
                record = self._record_evidence(
                    tenant_id=body["tenant_id"],
                    event_type=body["event_type"],
                    collector=body["collector"],
                    payload=body["payload"],
                    collected_at=body.get("collected_at"),
                )
                return 201, record.as_dict()
            if method == "POST" and path == "/v1/evidence/query":
                self.store.assert_tenant(body["tenant_id"])
                records = self.database.evidence_records(body["tenant_id"], body.get("event_type")) if self.database else self.evidence.list(tenant_id=body["tenant_id"], event_type=body.get("event_type"))
                return 200, {
                    "tenant_id": body["tenant_id"],
                    "records": [record.as_dict() for record in records],
                    "execution_permitted": False,
                }
            if method == "POST" and path == "/v1/evidence/verify":
                self.store.assert_tenant(body["tenant_id"])
                return 200, self.database.verify_evidence(body["tenant_id"]) if self.database else self.evidence.verify(tenant_id=body["tenant_id"])
            return 404, {"error": "route_not_found"}
        except KeyError as exc:
            return 404, {"error": str(exc)}
        except PermissionError as exc:
            return 403, {"error": str(exc)}
        except ConnectionError as exc:
            return 502, {"error": str(exc)}
        except (TypeError, ValueError) as exc:
            return 400, {"error": str(exc)}

    @staticmethod
    def _query_value(query: dict[str, list[str]], key: str) -> str:
        values = query.get(key, [])
        if len(values) != 1 or not values[0]:
            raise ValueError(f"{key} query parameter is required exactly once")
        return values[0]

    def _record_evidence(self, *, tenant_id: str, event_type: str, collector: str, payload: dict[str, Any], collected_at: str | None = None):
        if self.database:
            return self.database.record_evidence(tenant_id=tenant_id, event_type=event_type, collector=collector, payload=payload, collected_at=collected_at)
        return self.evidence.record(tenant_id=tenant_id, event_type=event_type, collector=collector, payload=payload, collected_at=collected_at)

    @staticmethod
    def _request_summary(request: AuthorizationRequest) -> dict[str, Any]:
        return {"request_id": str(request.request_id), "tenant_id": request.tenant_id,
                "actor_id": request.actor_id, "action": request.action, "target": request.target,
                "environment": request.environment, "capabilities": list(request.capabilities),
                "mode": request.mode, "reason": request.reason}

    @staticmethod
    def _manifest_summary(manifest: Any) -> dict[str, Any]:
        return {"connector_id": manifest.connector_id, "domain": manifest.domain,
                "version": manifest.version, "capabilities": list(manifest.capabilities),
                "network_destinations": list(manifest.network_destinations),
                "read_only_by_default": manifest.read_only_by_default}

    def _register_integration(self, body: dict[str, Any]) -> dict[str, Any]:
        tenant_id = str(body.get("tenant_id", ""))
        self.store.assert_tenant(tenant_id)
        protocol = str(body.get("protocol", ""))
        supported = {"rest_openapi", "mcp_http", "redfish", "snmp", "modbus_tcp", "bacnet_ip", "opcua", "mqtt", "ssh_readonly", "custom"}
        if protocol not in supported:
            raise ValueError("unsupported integration protocol")
        name = str(body.get("name", "")).strip()
        if not name or len(name) > 120:
            raise ValueError("name is required and must be at most 120 characters")
        base_url = str(body.get("base_url", "")).strip()
        parsed = urlsplit(base_url)
        schemes = {
            "rest_openapi": {"https", "http"}, "mcp_http": {"https", "http"},
            "redfish": {"https", "http"}, "custom": {"https", "http"},
            "snmp": {"snmp", "snmp+tls"}, "modbus_tcp": {"modbus+tcp", "modbus+tls"},
            "bacnet_ip": {"bacnet", "bacnet+secure"}, "opcua": {"opc.tcp", "opc.wss"},
            "mqtt": {"mqtts", "mqtt"}, "ssh_readonly": {"ssh"},
        }[protocol]
        if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint must use the protocol's URL scheme and contain no userinfo, query, or fragment")
        host = parsed.hostname.lower().rstrip(".")
        if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("unencrypted HTTP is allowed only for loopback test endpoints")
        allowed_hosts = body.get("allowed_hosts", [])
        if not isinstance(allowed_hosts, list) or not all(isinstance(x, str) for x in allowed_hosts):
            raise ValueError("allowed_hosts must be an explicit array of hostnames")
        normalized_hosts = sorted({x.strip().lower().rstrip(".") for x in allowed_hosts if x.strip()})
        if host not in normalized_hosts:
            raise ValueError("endpoint hostname must exactly match an explicit allowed_hosts entry")
        scopes = body.get("scopes", [])
        if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
            raise ValueError("scopes must be an array of least-privilege capability names")
        normalized_scopes = sorted({x.strip() for x in scopes if x.strip()})
        if any(not re.fullmatch(r"[A-Za-z0-9:._-]{1,100}", x) for x in normalized_scopes):
            raise ValueError("scope names may contain only letters, digits, colon, dot, underscore, and hyphen")
        credential_ref = str(body.get("credential_ref", "")).strip() or None
        if credential_ref and not re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", credential_ref):
            raise ValueError("credential_ref must be an environment/secret-manager reference name, never a secret value")
        auth_scheme = str(body.get("auth_scheme", "bearer")).strip().lower()
        if auth_scheme not in {"bearer", "http_basic"}:
            raise ValueError("auth_scheme must be bearer or http_basic")
        if auth_scheme == "http_basic" and protocol != "redfish":
            raise ValueError("HTTP Basic authentication is supported only by the Redfish adapter")
        item = {
            "name": name, "protocol": protocol, "vendor": str(body.get("vendor", "")).strip() or None,
            "product": str(body.get("product", "")).strip() or None, "base_url": base_url,
            "credential_ref": credential_ref, "allowed_hosts": normalized_hosts,
            "scopes": normalized_scopes, "access_mode": "read_only", "status": "draft",
            "config_json": json.dumps({"onboarding_state": "metadata_only", "probe_required": True, "auth_scheme": auth_scheme}),
        }
        if self.database:
            try:
                return dict(self.database.add_integration(tenant_id, item))
            except Exception as exc:
                raise ConnectionError("integration metadata could not be persisted") from exc
        local = {k: v for k, v in item.items() if k != "config_json"}
        local["config"] = {"onboarding_state": "metadata_only", "probe_required": True}
        self.integration_connections.setdefault(tenant_id, []).append(local)
        return local

    @staticmethod
    def _request_from_json(body: dict[str, Any]) -> AuthorizationRequest:
        return AuthorizationRequest(
            request_id=UUID(str(body["request_id"])),
            actor_id=body["actor_id"],
            action=body["action"],
            target=body["target"],
            environment=body["environment"],
            capabilities=tuple(body.get("capabilities", [])),
            mode=body.get("mode", "observe"),
            approvals=tuple(body.get("approvals", [])),
            second_approver=bool(body.get("second_approver", False)),
            reason=body.get("reason", ""),
            tenant_id=body["tenant_id"],
        )


def serve(*, host: str = "127.0.0.1", port: int = 8794, api: LocalControlPlaneApi | None = None) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("local API refuses non-loopback bind addresses")
    application = api or LocalControlPlaneApi()

    class Handler(BaseHTTPRequestHandler):
        def _respond(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, sort_keys=True, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            request_path = urlsplit(self.path).path
            static_assets = {
                "/assets/onboarding.js": "onboarding.js",
                "/assets/topology.js": "topology.js",
                "/assets/azure-prices.js": "azure-prices.js",
                "/assets/placement-comparison.js": "placement-comparison.js",
                "/assets/placement-scenarios.js": "placement-scenarios.js",
            }
            if request_path in static_assets:
                asset = Path(__file__).resolve().parents[2] / "ui" / static_assets[request_path]
                try:
                    data = asset.read_bytes()
                except OSError:
                    self._respond(HTTPStatus.NOT_FOUND, {"error": "console_asset_unavailable"})
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(data)
                return
            if request_path in {"/", "/index.html"}:
                page = Path(__file__).resolve().parents[2] / "ui" / "index.html"
                try:
                    data = page.read_bytes()
                except OSError:
                    self._respond(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "console_asset_unavailable"})
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            status, payload = application.dispatch("GET", self.path)
            self._respond(status, payload)

        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 70000:
                    raise ValueError("request body exceeds 70000 bytes")
                if self.path.split("?", 1)[0] == "/v1/placement/scenarios":
                    expected = {f"http://127.0.0.1:{self.server.server_address[1]}",
                                f"http://localhost:{self.server.server_address[1]}"}
                    if self.headers.get("Origin") not in expected:
                        self._respond(HTTPStatus.FORBIDDEN, {"error": "same_origin_required", "execution_permitted": False})
                        return
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("request body must be an object")
                status, payload = application.dispatch("POST", self.path, body)
            except (ValueError, json.JSONDecodeError) as exc:
                status, payload = HTTPStatus.BAD_REQUEST, {"error": str(exc)}
            self._respond(int(status), payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if application.database is not None:
            application.database.close()
