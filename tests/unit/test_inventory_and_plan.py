import unittest

from control_plane_core.connectors import ConnectorRegistry
from control_plane_core.inventory import SyntheticReadOnlyConnector
from control_plane_core.plan import OfflinePlanService


class InventoryAndPlanTests(unittest.TestCase):
    def test_synthetic_connector_is_read_only_and_tenant_scoped(self) -> None:
        registry = ConnectorRegistry()
        registry.register(SyntheticReadOnlyConnector("lab-kubernetes", "kubernetes", {"nodes": 1}))
        observations = registry.observe("lab-kubernetes", tenant_id="tenant-a", target="cluster-a", environment="lab")
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0].read_only)
        self.assertEqual(observations[0].tenant_id, "tenant-a")
        self.assertEqual(registry.manifests()[0].network_destinations, ())

    def test_offline_plan_evaluation_never_permits_execution(self) -> None:
        evaluation = OfflinePlanService().evaluate(
            {
                "format_version": "1.0",
                "terraform_version": "1.9.0",
                "resource_changes": [
                    {"address": "aws_s3_bucket.example", "change": {"actions": ["update"]}},
                ],
            }
        )
        self.assertEqual(evaluation.decision, "allow")
        self.assertFalse(evaluation.execution_permitted)

    def test_destructive_plan_is_conditional(self) -> None:
        evaluation = OfflinePlanService().evaluate(
            {
                "format_version": "1.0",
                "terraform_version": "1.9.0",
                "resource_changes": [
                    {"address": "aws_db_instance.example", "change": {"actions": ["delete"]}},
                ],
            }
        )
        self.assertEqual(evaluation.decision, "conditional")
        self.assertEqual(evaluation.destructive_count, 1)
        self.assertIn("destructive_change_requires_human_review", evaluation.reason_codes)

    def test_invalid_plan_action_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OfflinePlanService().evaluate(
                {
                    "format_version": "1.0",
                    "terraform_version": "1.9.0",
                    "resource_changes": [
                        {"address": "x", "change": {"actions": ["exec"]}},
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()
