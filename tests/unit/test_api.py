import unittest
from unittest.mock import patch
from uuid import uuid4

from control_plane_core.api import LocalControlPlaneApi, serve, validate_placement_snapshot
from control_plane_core.agents import AgentManifest, ToolDefinition
from control_plane_core.evidence import EvidenceLedger
from control_plane_core.inventory import SyntheticReadOnlyConnector


class LocalApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = LocalControlPlaneApi()
        self.api.register_connector(SyntheticReadOnlyConnector("lab-kubernetes", "kubernetes"))
        self.api.register_agent_tool(
            AgentManifest("inventory-agent", "tenant-a", "inventory", frozenset({"asset.inventory.read"}), ("sha256:" + "a" * 64,))
        )
        self.api.register_tool(ToolDefinition("asset.inventory.read", "inventory.read", True))
        self.api.dispatch("POST", "/v1/tenants", {"tenant_id": "tenant-a", "name": "Lab Tenant"})
        self.api.dispatch("POST", "/v1/identities", {"identity_id": "operator-a", "tenant_id": "tenant-a", "kind": "human"})
        self.api.dispatch("POST", "/v1/assets", {"asset_id": "lab-vm", "tenant_id": "tenant-a", "kind": "virtual-machine", "environment": "lab"})

    def test_health_is_explicitly_non_executing(self) -> None:
        status, payload = self.api.dispatch("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["execution"], "disabled")
        self.assertEqual(payload["credentials"], "disabled")
        self.assertEqual(payload["network"], "disabled")

    def test_readiness_is_not_liveness_and_requires_persistent_database(self) -> None:
        status, payload = self.api.dispatch("GET", "/readyz")
        self.assertEqual(status, 503)
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["checks"]["database"], "not_configured")
        self.assertFalse(payload["execution_permitted"])

    def test_database_routes_report_memory_mode_without_fabricating_analytics(self) -> None:
        status, database = self.api.dispatch("GET", "/v1/database/status")
        self.assertEqual(status, 200)
        self.assertEqual(database["status"], "not_configured")
        status, analytics = self.api.dispatch("GET", "/v1/analytics/overview?tenant_id=tenant-a")
        self.assertEqual(status, 503)
        self.assertEqual(analytics["error"], "database_not_configured")

    def test_cost_analytics_fails_closed_without_postgres_schema(self) -> None:
        status, payload = self.api.dispatch("GET", "/v1/analytics/costs?tenant_id=tenant-a")
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"], "database_not_configured")
        self.assertFalse(payload["execution_permitted"])

    def test_placement_snapshot_requires_dated_sources_and_postgres(self) -> None:
        payload = {
            "schema_version": "placement-tco-comparison.v1",
            "assumptions": {"currency": "USD", "horizon_months": 36},
            "sources": {side: {"type": "Invoice / billing export", "reference": "billing-2026-09", "observed_on": "2026-09-25"}
                        for side in ("onprem", "cloud")},
            "results": {side: {"npv": 0} for side in ("onprem", "cloud")},
        }
        name, encoded, digest, version = validate_placement_snapshot({"name": "Lab TCO", "payload": payload})
        self.assertEqual(name, "Lab TCO")
        self.assertEqual(version, payload["schema_version"])
        self.assertEqual(len(digest), 64)
        status, missing_db = self.api.dispatch("POST", "/v1/placement/scenarios", {
            "tenant_id": "tenant-a", "name": name, "payload": payload,
        })
        self.assertEqual(status, 503)
        self.assertEqual(missing_db["error"], "placement_snapshot_database_required")
        status, missing_db = self.api.dispatch("GET", "/v1/placement/scenarios?tenant_id=tenant-a")
        self.assertEqual(status, 503)
        bad = {**payload, "sources": {**payload["sources"], "cloud": {**payload["sources"]["cloud"], "observed_on": "not-a-date"}}}
        status, invalid = self.api.dispatch("POST", "/v1/placement/scenarios", {
            "tenant_id": "tenant-a", "name": name, "payload": bad,
        })
        self.assertEqual(status, 400)
        self.assertIn("observation date", invalid["error"])

    def test_placement_snapshot_routes_use_database_and_preserve_tenant_scope(self) -> None:
        class SnapshotRepository:
            def __init__(self):
                self.rows = []

            def save_placement_snapshot(self, tenant_id, **fields):
                row = {"scenario_id": "snapshot-1", "tenant_id": tenant_id, **fields}
                self.rows.append(row)
                return row

            def placement_snapshots(self, tenant_id):
                return [row for row in self.rows if row["tenant_id"] == tenant_id]

        self.api.database = SnapshotRepository()
        payload = {
            "schema_version": "placement-tco-comparison.v1",
            "assumptions": {"currency": "USD", "horizon_months": 24},
            "sources": {side: {"type": "Vendor quote / contract", "reference": "quote-42", "observed_on": "2026-09-25"}
                        for side in ("onprem", "cloud")},
            "results": {side: {"npv": 1} for side in ("onprem", "cloud")},
        }
        status, created = self.api.dispatch("POST", "/v1/placement/scenarios", {
            "tenant_id": "tenant-a", "name": "Lab case", "payload": payload,
        })
        self.assertEqual(status, 201)
        self.assertEqual(created["status"], "draft_snapshot")
        status, listed = self.api.dispatch("GET", "/v1/placement/scenarios?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(len(listed["scenarios"]), 1)
        self.assertEqual(listed["scenarios"][0]["tenant_id"], "tenant-a")

    def test_evidence_routes_use_configured_database_repository(self) -> None:
        class Repository:
            def __init__(self):
                self.ledger = EvidenceLedger()

            def record_evidence(self, **fields):
                return self.ledger.record(**fields)

            def evidence_records(self, tenant_id, event_type=None):
                return self.ledger.list(tenant_id=tenant_id, event_type=event_type)

            def verify_evidence(self, tenant_id):
                return self.ledger.verify(tenant_id=tenant_id)

        self.api.database = Repository()
        status, appended = self.api.dispatch("POST", "/v1/evidence/append", {
            "tenant_id": "tenant-a", "event_type": "demo.persisted", "collector": "unit-test",
            "payload": {"tenant_id": "tenant-a", "source": "synthetic"},
        })
        self.assertEqual(status, 201)
        status, queried = self.api.dispatch("POST", "/v1/evidence/query", {"tenant_id": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertEqual(queried["records"][0]["record_sha256"], appended["record_sha256"])
        status, verified = self.api.dispatch("POST", "/v1/evidence/verify", {"tenant_id": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertEqual(verified["records"], 1)

    def test_command_center_read_models_are_tenant_scoped(self) -> None:
        status, overview = self.api.dispatch("GET", "/v1/overview")
        self.assertEqual(status, 200)
        self.assertEqual(overview["tenants"][0]["tenant_id"], "tenant-a")
        self.assertFalse(overview["execution_permitted"])
        status, inventory = self.api.dispatch("GET", "/v1/inventory?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(inventory["assets"][0]["asset_id"], "lab-vm")
        status, rejected = self.api.dispatch("GET", "/v1/inventory?tenant_id=tenant-missing")
        self.assertEqual(status, 404)
        self.assertIn("tenant not found", rejected["error"])
        status, missing = self.api.dispatch("GET", "/v1/requests")
        self.assertEqual(status, 400)
        self.assertIn("tenant_id query parameter", missing["error"])

    def test_connector_onboarding_creates_read_only_draft_without_secret_material(self) -> None:
        status, catalog = self.api.dispatch("GET", "/v1/integrations/catalog")
        self.assertEqual(status, 200)
        self.assertIn("redfish", {item["id"] for item in catalog["protocols"]})
        status, draft = self.api.dispatch("POST", "/v1/integrations/connections", {
            "tenant_id": "tenant-a", "name": "Lab Redfish", "protocol": "redfish",
            "vendor": "Example OEM", "product": "BMC v1", "base_url": "https://bmc.lab.example/redfish/v1",
            "allowed_hosts": ["bmc.lab.example"], "credential_ref": "BMC_READONLY_TOKEN",
            "scopes": ["inventory.read", "sensors.read"],
        })
        self.assertEqual(status, 201)
        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["access_mode"], "read_only")
        self.assertNotIn("secret", draft)
        status, connections = self.api.dispatch("GET", "/v1/integrations/connections?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(connections["connections"][0]["name"], "Lab Redfish")
        self.assertEqual(connections["persistence"], "in_memory")

    def test_azure_retail_price_route_is_read_only_and_rejects_duplicate_filters(self) -> None:
        expected = {"provider": "Microsoft Azure Retail Prices API", "prices": [], "execution_permitted": False}
        with patch.object(self.api.live_integrations, "azure_retail_prices", return_value=expected) as lookup:
            status, payload = self.api.dispatch("GET", "/v1/integrations/prices/azure-retail?region=eastus")
            self.assertEqual(status, 200)
            self.assertEqual(payload, expected)
            self.assertEqual(lookup.call_args.kwargs["service_name"], "Virtual Machines")
            status, invalid = self.api.dispatch("GET", "/v1/integrations/prices/azure-retail?region=eastus&region=westus")
        self.assertEqual(status, 400)
        self.assertIn("only once", invalid["error"])

    def test_google_cloud_catalog_route_is_read_only_and_rejects_duplicate_filters(self) -> None:
        expected = {"provider": "Google Cloud Billing Catalog API", "prices": [], "execution_permitted": False}
        with patch.object(self.api.live_integrations, "google_cloud_retail_prices", return_value=expected) as lookup:
            status, payload = self.api.dispatch("GET", "/v1/integrations/prices/google-cloud-retail?region=us-central1&sku_query=N2")
            self.assertEqual(status, 200)
            self.assertEqual(payload, expected)
            self.assertEqual(lookup.call_args.kwargs["service_name"], "Compute Engine")
            status, invalid = self.api.dispatch("GET", "/v1/integrations/prices/google-cloud-retail?region=us-central1&region=europe-west1&sku_query=N2")
        self.assertEqual(status, 400)
        self.assertIn("only once", invalid["error"])

    def test_connector_draft_rejects_unlisted_hosts_and_secret_values(self) -> None:
        base = {"tenant_id": "tenant-a", "name": "Unsafe", "protocol": "rest_openapi",
                "base_url": "https://api.vendor.example/v1", "allowed_hosts": ["other.example"], "scopes": ["inventory.read"]}
        status, payload = self.api.dispatch("POST", "/v1/integrations/connections", base)
        self.assertEqual(status, 400)
        self.assertIn("exactly match", payload["error"])
        base["allowed_hosts"] = ["api.vendor.example"]
        base["credential_ref"] = "actual-token-value"
        status, payload = self.api.dispatch("POST", "/v1/integrations/connections", base)
        self.assertEqual(status, 400)
        self.assertIn("reference name", payload["error"])

    def test_request_plan_and_approval_stay_tenant_scoped(self) -> None:
        request_id = str(uuid4())
        status, response = self.api.dispatch(
            "POST",
            "/v1/authorization-requests",
            {
                "request_id": request_id,
                "tenant_id": "tenant-a",
                "actor_id": "operator-a",
                "action": "inventory.local",
                "target": "lab-vm",
                "environment": "lab",
                "mode": "observe",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(response["decision"]["decision"], "allow")
        status, plan = self.api.dispatch("POST", "/v1/plans", {"request_id": request_id})
        self.assertEqual(status, 201)
        self.assertEqual(plan["execution_permitted"], False)
        status, approval = self.api.dispatch(
            "POST",
            "/v1/approvals",
            {
                "approval_id": "approval-a",
                "request_id": request_id,
                "approver_id": "operator-a",
                "tenant_id": "tenant-a",
                "signature_verified": True,
                "expires_at": "2099-01-01T00:00:00Z",
            },
        )
        # Unsigned client assertions must not create an approval record.
        self.assertEqual(status, 400)
        self.assertIn("signed_record", approval["error"])

    def test_cross_tenant_target_is_rejected(self) -> None:
        self.api.dispatch("POST", "/v1/tenants", {"tenant_id": "tenant-b", "name": "Other Tenant"})
        self.api.dispatch("POST", "/v1/identities", {"identity_id": "operator-b", "tenant_id": "tenant-b", "kind": "human"})
        status, payload = self.api.dispatch(
            "POST",
            "/v1/authorization-requests",
            {
                "request_id": str(uuid4()),
                "tenant_id": "tenant-b",
                "actor_id": "operator-b",
                "action": "inventory.local",
                "target": "lab-vm",
                "environment": "lab",
                "mode": "observe",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("tenant boundary", payload["error"])

    def test_api_rejects_public_bind(self) -> None:
        with self.assertRaises(ValueError):
            serve(host="0.0.0.0")

    def test_inventory_and_offline_plan_routes_are_non_executing(self) -> None:
        status, response = self.api.dispatch(
            "POST",
            "/v1/inventory/observe",
            {"connector_id": "lab-kubernetes", "tenant_id": "tenant-a", "target": "lab-vm", "environment": "lab"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(response["observations"][0]["read_only"])
        self.assertEqual(response["inventory_persistence"], "in_memory")
        status, inventory = self.api.dispatch("GET", "/v1/inventory?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(inventory["assets"][0]["kind"], "kubernetes")
        status, evaluation = self.api.dispatch(
            "POST",
            "/v1/plan-evaluations",
            {
                "artifact": {
                    "format_version": "1.0",
                    "terraform_version": "1.9.0",
                    "resource_changes": [],
                }
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(evaluation["execution_permitted"])

    def test_live_inventory_observations_use_atomic_database_repository_path(self) -> None:
        class Repository:
            def __init__(self):
                self.batch = None

            def persist_inventory_observations(self, tenant_id, observations):
                self.batch = (tenant_id, observations)
                return [{"asset_id": item["resource_id"], "tenant_id": tenant_id,
                         "kind": item["resource_type"], "environment": item["environment"],
                         "status": "active", "observed_at": item["observed_at"]}
                        for item in observations]

        repository = Repository()
        self.api.database = repository
        status, response = self.api.dispatch("POST", "/v1/inventory/observe", {
            "connector_id": "lab-kubernetes", "tenant_id": "tenant-a", "target": "lab-vm", "environment": "lab",
        })
        self.assertEqual(status, 200)
        self.assertEqual(response["inventory_persistence"], "postgres")
        self.assertEqual(repository.batch[0], "tenant-a")
        self.assertIn("lab-vm", self.api.store.assets)

    def test_agent_tool_authorization_route_is_default_deny(self) -> None:
        status, decision = self.api.dispatch(
            "POST",
            "/v1/agent-tool-calls/authorize",
            {
                "call_id": str(uuid4()),
                "agent_id": "inventory-agent",
                "tenant_id": "tenant-a",
                "tool_id": "asset.inventory.read",
                "target": "lab-vm",
                "mode": "observe",
                "capability": "inventory.read",
                "arguments": {},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision["decision"], "allow")
        self.assertFalse(decision["execution_permitted"])

    def test_graph_drift_and_verification_routes_remain_non_executing(self) -> None:
        status, _ = self.api.dispatch("POST", "/v1/graph/nodes", {"tenant_id": "tenant-a", "node_id": "identity-a", "kind": "identity"})
        self.assertEqual(status, 201)
        status, _ = self.api.dispatch("POST", "/v1/graph/nodes", {"tenant_id": "tenant-a", "node_id": "asset-a", "kind": "asset"})
        self.assertEqual(status, 201)
        status, edge = self.api.dispatch(
            "POST", "/v1/graph/edges", {"tenant_id": "tenant-a", "source_id": "identity-a", "target_id": "asset-a", "relation": "can_access"}
        )
        self.assertEqual(status, 201)
        status, graph = self.api.dispatch("POST", "/v1/graph/query", {"tenant_id": "tenant-a", "root_id": "asset-a"})
        self.assertEqual(status, 200)
        self.assertEqual(len(graph["edges"]), 1)
        self.assertFalse(graph["execution_permitted"])
        status, drift = self.api.dispatch(
            "POST", "/v1/drift/evaluate", {"tenant_id": "tenant-a", "resource_id": "asset-a", "desired": {"state": "ready"}, "observed": {"state": "ready"}}
        )
        self.assertEqual(status, 200)
        self.assertFalse(drift["drifted"])
        status, verification = self.api.dispatch(
            "POST",
            "/v1/verification/evaluate",
            {
                "tenant_id": "tenant-a",
                "resource_id": "asset-a",
                "receipt": {
                    "receipt_id": str(uuid4()),
                    "plan_id": str(uuid4()),
                    "runner_id": "sim-runner-api",
                    "tenant_id": "tenant-a",
                    "resource_id": "asset-a",
                },
                "expected_state": {"state": "ready"},
                "observed_state": {"state": "ready"},
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verification["verified"])
        self.assertFalse(verification["execution_permitted"])

    def test_evidence_routes_are_tenant_partitioned(self) -> None:
        status, record = self.api.dispatch(
            "POST",
            "/v1/evidence/append",
            {"tenant_id": "tenant-a", "event_type": "operator.note", "collector": "test", "payload": {"tenant_id": "tenant-a", "note": "reviewed"}},
        )
        self.assertEqual(status, 201)
        self.assertEqual(record["sequence"], 1)
        status, query = self.api.dispatch("POST", "/v1/evidence/query", {"tenant_id": "tenant-a", "event_type": "operator.note"})
        self.assertEqual(status, 200)
        self.assertEqual(len(query["records"]), 1)
        self.assertFalse(query["execution_permitted"])
        status, verification = self.api.dispatch("POST", "/v1/evidence/verify", {"tenant_id": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(verification["records"], 1)
        status, payload = self.api.dispatch(
            "POST",
            "/v1/evidence/append",
            {"tenant_id": "tenant-a", "event_type": "operator.note", "collector": "test", "payload": {"tenant_id": "tenant-b"}},
        )
        self.assertEqual(status, 403)
        self.assertIn("tenant boundary", payload["error"])


if __name__ == "__main__":
    unittest.main()
