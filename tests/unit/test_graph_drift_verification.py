import unittest
from uuid import uuid4

from control_plane_core.drift import DriftDetector
from control_plane_core.graph import GraphEdge, GraphNode, RelationshipGraph
from control_plane_core.lifecycle import ExecutionReceipt
from control_plane_core.verification import PostChangeVerifier


class GraphDriftVerificationTests(unittest.TestCase):
    def test_graph_rejects_cross_tenant_edges_and_isolates_queries(self) -> None:
        graph = RelationshipGraph()
        graph.add_node(GraphNode("asset-a", "tenant-a", "asset"))
        graph.add_node(GraphNode("identity-a", "tenant-a", "identity"))
        graph.add_node(GraphNode("asset-b", "tenant-b", "asset"))
        with self.assertRaises(PermissionError):
            graph.add_edge(GraphEdge(uuid4(), "tenant-a", "asset-a", "asset-b", "owns"))
        graph.add_edge(GraphEdge(uuid4(), "tenant-a", "identity-a", "asset-a", "can_access"))
        result = graph.query(tenant_id="tenant-a", root_id="asset-a", depth=1)
        self.assertEqual({node.node_id for node in result.nodes}, {"asset-a", "identity-a"})
        self.assertTrue(all(node.tenant_id == "tenant-a" for node in result.nodes))
        with self.assertRaises(PermissionError):
            graph.query(tenant_id="tenant-b", root_id="asset-a")

    def test_drift_hashes_are_deterministic_and_never_executable(self) -> None:
        detector = DriftDetector()
        first = detector.compare(
            tenant_id="tenant-a",
            resource_id="cluster-a",
            desired={"replicas": 3, "labels": {"tier": "api"}},
            observed={"labels": {"tier": "worker"}, "replicas": 3},
        )
        second = detector.compare(
            tenant_id="tenant-a",
            resource_id="cluster-a",
            desired={"labels": {"tier": "api"}, "replicas": 3},
            observed={"replicas": 3, "labels": {"tier": "worker"}},
        )
        self.assertTrue(first.drifted)
        self.assertEqual(first.desired_hash, second.desired_hash)
        self.assertEqual(first.observed_hash, second.observed_hash)
        self.assertEqual(first.changed_fields, ("labels.tier",))
        self.assertFalse(first.execution_permitted)

    def test_verifier_passes_safe_match_and_flags_drift_for_rollback(self) -> None:
        receipt = ExecutionReceipt(
            receipt_id=uuid4(),
            plan_id=uuid4(),
            runner_id="sim-runner-test",
            tenant_id="tenant-a",
            resource_id="vm-a",
        )
        verifier = PostChangeVerifier()
        passed = verifier.verify(
            receipt=receipt,
            tenant_id="tenant-a",
            resource_id="vm-a",
            expected_state={"status": "healthy"},
            observed_state={"status": "healthy"},
        )
        self.assertTrue(passed.verified)
        self.assertFalse(passed.rollback_required)
        self.assertFalse(passed.execution_permitted)
        failed = verifier.verify(
            receipt=receipt,
            tenant_id="tenant-a",
            resource_id="vm-a",
            expected_state={"status": "healthy"},
            observed_state={"status": "degraded"},
        )
        self.assertFalse(failed.verified)
        self.assertTrue(failed.rollback_required)
        self.assertIn("post_change_drift_detected", failed.checks)

    def test_verifier_rejects_cross_tenant_receipt(self) -> None:
        receipt = ExecutionReceipt(
            receipt_id=uuid4(),
            plan_id=uuid4(),
            runner_id="sim-runner-test",
            tenant_id="tenant-a",
            resource_id="vm-a",
        )
        with self.assertRaises(PermissionError):
            PostChangeVerifier().verify(
                receipt=receipt,
                tenant_id="tenant-b",
                resource_id="vm-a",
                expected_state={},
                observed_state={},
            )

    def test_verifier_rejects_unsafe_receipt_without_executing(self) -> None:
        receipt = ExecutionReceipt(
            receipt_id=uuid4(),
            plan_id=uuid4(),
            runner_id="sim-runner-test",
            simulation=False,
            credentials_issued=True,
            network_calls=1,
            tenant_id="tenant-a",
            resource_id="vm-a",
        )
        report = PostChangeVerifier().verify(
            receipt=receipt,
            tenant_id="tenant-a",
            resource_id="vm-a",
            expected_state={},
            observed_state={},
        )
        self.assertFalse(report.verified)
        self.assertTrue(report.rollback_required)
        self.assertFalse(report.execution_permitted)
        self.assertEqual(report.credentials_issued, False)
        self.assertEqual(report.network_calls, 0)


if __name__ == "__main__":
    unittest.main()
