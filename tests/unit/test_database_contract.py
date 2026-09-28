import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class DatabaseContractTests(unittest.TestCase):
    def test_schema_covers_operational_domains_and_enables_tenant_rls(self) -> None:
        schema = (ROOT / "database" / "schema.sql").read_text()
        required = {
            "tenants", "sites", "facilities", "racks", "assets", "integration_connections",
            "identities", "role_bindings", "privileged_sessions", "authorization_requests", "change_plans",
            "approvals", "agents", "model_endpoints", "mcp_servers", "mcp_tools", "graph_edges",
            "sensor_definitions", "sensor_readings", "energy_readings", "maintenance_rules",
            "maintenance_work_orders", "kpi_definitions", "kpi_observations", "forecast_runs",
            "forecast_points", "evidence_events", "benchmark_runs",
        }
        for table in required:
            self.assertIn(f"CREATE TABLE {table} ", schema)
        self.assertIn("ENABLE ROW LEVEL SECURITY", schema)
        self.assertIn("FORCE ROW LEVEL SECURITY", schema)
        repository = (ROOT / "src" / "control_plane_core" / "database.py").read_text()
        self.assertIn("def readiness(", repository)
        self.assertIn("SET TRANSACTION READ ONLY", repository)
        self.assertIn("relforcerowsecurity", repository)
        self.assertIn("current_setting(''opsatlas.tenant_id''", schema)
        self.assertNotIn("api_key text", schema.lower())

    def test_demo_seed_is_visibly_synthetic_and_reset_is_demo_gated(self) -> None:
        seed = (ROOT / "database" / "demo_seed.sql").read_text()
        reset = (ROOT / "scripts" / "db-reset-demo.sh").read_text()
        self.assertIn('"synthetic":true', seed)
        self.assertIn("not_a_live_probe", seed)
        self.assertIn("RESET_${DB_NAME}", reset)
        self.assertIn("opsatlas_(demo|dev)", reset)
        self.assertIn("DELETE FROM opsatlas.tenants WHERE slug='opsatlas-demo'", reset)

    def test_demo_seed_populates_telemetry_kpis_forecasts_and_connectors(self) -> None:
        seed = (ROOT / "database" / "demo_seed.sql").read_text()
        for table in ("integration_connections", "mcp_servers", "sensor_readings", "energy_readings",
                      "maintenance_work_orders", "kpi_observations", "forecast_points", "evidence_events"):
            self.assertIn(f"INSERT INTO opsatlas.{table}", seed)

    def test_synthetic_analytics_requires_explicit_demo_opt_in(self) -> None:
        api = (ROOT / "src" / "control_plane_core" / "api.py").read_text()
        repository = (ROOT / "src" / "control_plane_core" / "database.py").read_text()
        ui = (ROOT / "ui" / "index.html").read_text()
        self.assertIn('query.get("demo") == ["synthetic"]', api)
        self.assertIn('tenant_source["synthetic"] and not include_synthetic_demo', repository)
        self.assertIn("show_synthetic = bool(include_synthetic_demo and demo_tenant)", repository)
        self.assertIn("searchParams.set('demo','synthetic')", ui)
        self.assertIn("SYNTHETIC DEMO · NOT LIVE", ui)


if __name__ == "__main__":
    unittest.main()
