import unittest

from control_plane_core.lifecycle import ChangeLifecycle
from control_plane_core.runner import CapabilityBroker, CredentialBroker, ExecutionOrchestrator
from control_plane_core.service import ControlPlane, request


class RunnerBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.control_plane = ControlPlane.local()

    def test_capability_token_is_short_lived_scoped_and_non_secret(self) -> None:
        lifecycle = ChangeLifecycle.start(
            request(actor_id="operator-1", action="vm.resize", target="lab-vm", mode="mutate"),
            self.control_plane,
        )
        lifecycle.approve("approval-1")
        dispatch = ExecutionOrchestrator().dispatch_simulated(lifecycle, scope=("plan.read",))
        self.assertTrue(dispatch.capability_token.valid_at())
        self.assertEqual(dispatch.capability_token.environment, "lab")
        self.assertFalse(dispatch.capability_token.secret_material)
        self.assertFalse(dispatch.runner_request.network_allowed)
        self.assertFalse(dispatch.runner_request.credentials_allowed)

    def test_real_credential_broker_is_denied(self) -> None:
        with self.assertRaises(PermissionError):
            CredentialBroker().issue(tenant_id="tenant-a", target="lab-vm", capability="cloud", environment="lab")

    def test_production_capability_token_is_denied(self) -> None:
        with self.assertRaises(PermissionError):
            CapabilityBroker().issue(plan_id=lifecycle_id(), environment="production", scope=("plan.read",))

    def test_forbidden_scope_is_denied(self) -> None:
        with self.assertRaises(PermissionError):
            CapabilityBroker().issue(plan_id=lifecycle_id(), environment="lab", scope=("cloud_credentials",))


def lifecycle_id():
    from uuid import uuid4

    return uuid4()


if __name__ == "__main__":
    unittest.main()
