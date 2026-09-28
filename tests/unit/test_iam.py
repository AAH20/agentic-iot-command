import unittest
from uuid import uuid4

from control_plane_core.iam import BreakGlassService, SessionGateway, WorkloadIdentityBroker, WorkloadIdentityRequest


class IamBoundaryTests(unittest.TestCase):
    def test_workload_identity_never_mints_real_credentials(self) -> None:
        decision = WorkloadIdentityBroker().evaluate(
            WorkloadIdentityRequest(uuid4(), "agent-a", "tenant-a", "lab-vm", ("inventory.read",), "lab", 300)
        )
        self.assertEqual(decision.decision, "deny")
        self.assertFalse(decision.credential_issued)
        self.assertIn("credential_minting_disabled_in_local_core", decision.reason_codes)

    def test_session_gateway_records_open_and_close_without_exposing_credentials(self) -> None:
        gateway = SessionGateway()
        opened = gateway.open(tenant_id="tenant-a", identity_id="operator-a", target="lab-vm", approved=True)
        self.assertEqual(opened.event_type, "opened")
        self.assertFalse(opened.credentials_exposed)
        closed = gateway.close(session_id=opened.session_id, tenant_id="tenant-a")
        self.assertEqual(closed.event_type, "closed")
        self.assertEqual(len(gateway.events), 2)

    def test_session_close_cannot_cross_tenant(self) -> None:
        gateway = SessionGateway()
        opened = gateway.open(tenant_id="tenant-a", identity_id="operator-a", target="lab-vm", approved=True)
        with self.assertRaises(PermissionError):
            gateway.close(session_id=opened.session_id, tenant_id="tenant-b")

    def test_break_glass_requires_dual_control_and_post_review(self) -> None:
        service = BreakGlassService()
        denied = service.evaluate(
            request_id=uuid4(), tenant_id="tenant-a", requester_id="operator-a", target="prod-vm",
            reason="contain incident", approver_ids=("approver-a",), expires_in_seconds=300, environment="production"
        )
        self.assertEqual(denied.decision, "deny")
        approved = service.evaluate(
            request_id=uuid4(), tenant_id="tenant-a", requester_id="operator-a", target="prod-vm",
            reason="contain incident", approver_ids=("approver-a", "approver-b"), expires_in_seconds=300, environment="production"
        )
        self.assertEqual(approved.decision, "conditional")
        self.assertTrue(approved.post_review_required)
        self.assertFalse(approved.credential_issued)

    def test_break_glass_regulated_boundary_is_denied(self) -> None:
        decision = BreakGlassService().evaluate(
            request_id=uuid4(), tenant_id="tenant-a", requester_id="operator-a", target="regulated-vm",
            reason="contain incident", approver_ids=("approver-a", "approver-b"), expires_in_seconds=300, environment="regulated"
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("regulated_boundary_requires_separate_authority", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
