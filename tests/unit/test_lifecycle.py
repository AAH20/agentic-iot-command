import unittest

from control_plane_core.lifecycle import ChangeLifecycle
from control_plane_core.service import ControlPlane, request


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.control_plane = ControlPlane.local()

    def test_lab_lifecycle_requires_approval_then_verifies(self) -> None:
        lifecycle = ChangeLifecycle.start(
            request(actor_id="operator-1", action="vm.resize", target="lab-vm", mode="mutate"),
            self.control_plane,
        )
        self.assertEqual(lifecycle.state, "approval_pending")
        lifecycle.approve("approval-1")
        self.assertEqual(lifecycle.state, "approved")
        receipt = lifecycle.dispatch_simulated()
        self.assertTrue(receipt.simulation)
        self.assertFalse(receipt.credentials_issued)
        self.assertEqual(receipt.network_calls, 0)
        verification = lifecycle.verify(success=True)
        self.assertTrue(verification.verified)
        self.assertEqual(lifecycle.state, "verified")

    def test_failed_simulation_can_be_rolled_back(self) -> None:
        lifecycle = ChangeLifecycle.start(
            request(actor_id="operator-1", action="vm.resize", target="lab-vm", mode="mutate"),
            self.control_plane,
        )
        lifecycle.approve("approval-1")
        lifecycle.dispatch_simulated()
        lifecycle.verify(success=False)
        lifecycle.rollback()
        self.assertEqual(lifecycle.state, "rolled_back")

    def test_production_cannot_be_dispatched_by_simulation_runner(self) -> None:
        lifecycle = ChangeLifecycle.start(
            request(
                actor_id="operator-1",
                action="cluster.patch",
                target="prod-cluster",
                environment="production",
                mode="mutate",
            ),
            self.control_plane,
        )
        lifecycle.approve("approval-1")
        self.assertEqual(lifecycle.state, "approval_pending")
        lifecycle.approve("approval-2", second_approver=True)
        self.assertEqual(lifecycle.state, "approved")
        with self.assertRaises(PermissionError):
            lifecycle.dispatch_simulated()


if __name__ == "__main__":
    unittest.main()
