import unittest

from control_plane_core.service import ControlPlane, request


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.control_plane = ControlPlane.local()

    def test_read_only_observation_is_allowed_without_execution(self) -> None:
        decision = self.control_plane.authorize(
            request(actor_id="operator-1", action="inventory.local", target="lab-host")
        )
        self.assertEqual(decision.decision, "allow")
        self.assertFalse(decision.execution_permitted)

    def test_mutation_requires_approval(self) -> None:
        decision = self.control_plane.authorize(
            request(actor_id="operator-1", action="vm.resize", target="lab-vm", mode="mutate")
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("approval_required", decision.reason_codes)

    def test_production_mutation_requires_dual_control(self) -> None:
        decision = self.control_plane.authorize(
            request(
                actor_id="operator-1",
                action="cluster.patch",
                target="prod-cluster",
                environment="production",
                mode="mutate",
                approvals=("approval-1",),
            )
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("second_approver_required", decision.reason_codes)

    def test_expanded_capability_is_denied_by_local_core(self) -> None:
        decision = self.control_plane.authorize(
            request(
                actor_id="operator-1",
                action="cluster.patch",
                target="lab-cluster",
                mode="mutate",
                approvals=("approval-1",),
                capabilities=("cloud_credentials",),
            )
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("expanded_capability_requires_isolated_runner", decision.reason_codes)

    def test_scoped_lab_mutation_can_be_authorized_but_is_not_executed(self) -> None:
        decision = self.control_plane.authorize(
            request(
                actor_id="operator-1",
                action="vm.resize",
                target="lab-vm",
                mode="mutate",
                approvals=("approval-1",),
            )
        )
        self.assertEqual(decision.decision, "allow")
        self.assertTrue(decision.execution_permitted)

    def test_regulated_boundary_is_denied(self) -> None:
        decision = self.control_plane.authorize(
            request(
                actor_id="operator-1",
                action="inventory.local",
                target="regulated-host",
                environment="regulated",
            )
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("regulated_boundary_requires_separate_control_plane", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
