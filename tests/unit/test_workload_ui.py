from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WorkloadWorkbenchUiTests(unittest.TestCase):
    def test_workload_and_critical_grc_views_are_present_and_fail_closed(self):
        ui = (ROOT / "ui" / "index.html").read_text()
        self.assertIn('"workloads","▣","Suggested workloads"', ui)
        self.assertIn('"critical","⚿","Critical &amp; GRC"', ui)
        self.assertIn("data-workload-brief", ui)
        self.assertIn("workload.blueprint.plan", ui)
        self.assertIn("execution_permitted:false", ui)
        self.assertIn("Evidence required", ui)

    def test_purple_team_control_is_evidence_only_and_has_readiness_contract(self):
        ui = (ROOT / "ui" / "index.html").read_text()
        readiness = (ROOT / "docs" / "PURPLE_TEAM_READINESS.md").read_text()
        self.assertIn("Purple-team lab isolation & detection evidence", ui)
        self.assertIn("benign replay/simulation", ui)
        self.assertIn("not a command-and-control server", readiness)
        self.assertIn("configured` → `probed` → `validated`", readiness)
        self.assertIn("signed policy", readiness)
        self.assertIn("do not infer absence of activity", readiness.lower())

    def test_onboarding_and_graph_modules_keep_local_preferences_and_observation_boundary(self):
        root = Path(__file__).resolve().parents[2]
        ui = (root / "ui" / "index.html").read_text()
        onboarding = (root / "ui" / "onboarding.js").read_text()
        graph = (root / "ui" / "topology.js").read_text()
        api = (root / "src" / "control_plane_core" / "api.py").read_text()
        self.assertIn('src="/assets/onboarding.js"', ui)
        self.assertIn('src="/assets/topology.js"', ui)
        self.assertIn("preferences_local_only", onboarding)
        self.assertIn("execution_permitted:false", onboarding)
        self.assertIn("breadth-first trace O(V+E)", graph)
        self.assertIn('"/assets/topology.js": "topology.js"', api)
        self.assertIn("agentic-graph-data", graph)
        self.assertIn("Candidate framework crosswalks", ui)
        self.assertIn("weapon-control", ui)

    def test_placement_comparison_is_sourced_local_and_non_authorizing(self):
        root = Path(__file__).resolve().parents[2]
        ui = (root / "ui" / "placement-comparison.js").read_text()
        api = (root / "src" / "control_plane_core" / "api.py").read_text()
        self.assertIn('dataset.view = "placement"', ui)
        self.assertIn('id="placement-panel-tco"', ui)
        self.assertIn('id="placement-panel-fit"', ui)
        self.assertIn('id="placement-panel-gates"', ui)
        self.assertIn("blank costs never count as zero", ui.lower())
        self.assertIn("browser memory only; not sent to server", ui)
        self.assertIn("cost-only comparison", ui)
        self.assertIn("/assets/placement-comparison.js", api)
        persistence = (root / "ui" / "placement-scenarios.js").read_text()
        migration = (root / "database" / "migrations" / "004_placement_comparison_snapshots.sql").read_text()
        self.assertIn("Save draft snapshot", persistence)
        self.assertIn("not approved estimates", persistence)
        self.assertIn("placement_comparison_snapshots", migration)
        self.assertIn("FORCE ROW LEVEL SECURITY", migration)
        self.assertIn("/assets/placement-scenarios.js", api)


if __name__ == "__main__":
    unittest.main()
