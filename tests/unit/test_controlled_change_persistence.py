import unittest
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from control_plane_core.api import LocalControlPlaneApi
from control_plane_core.registry import ApprovalRecord


class WorkflowRepository:
    def __init__(self):
        self.rows = {}
        self.events = []

    def add_request(self, request, decision):
        self.events.append(("request", request.request_id))

    def save_change_workflow(self, *, tenant_id, plan, event_type, event_payload, create=False):
        key = plan["plan_id"]
        if create and key in self.rows:
            raise ValueError("duplicate workflow")
        if not create and key not in self.rows:
            raise KeyError("workflow missing")
        self.rows[key] = plan
        self.events.append((event_type, event_payload["state"]))

    def persisted_change_workflows(self, tenant_id):
        return [{"plan": plan} for plan in self.rows.values()]


class ControlledChangePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.api = LocalControlPlaneApi()
        self.api.dispatch("POST", "/v1/tenants", {"tenant_id": "tenant-a", "name": "Tenant A"})
        self.api.dispatch("POST", "/v1/identities", {"identity_id": "operator-a", "tenant_id": "tenant-a", "kind": "human"})
        self.api.dispatch("POST", "/v1/assets", {"asset_id": "lab-vm", "tenant_id": "tenant-a", "kind": "vm", "environment": "lab"})
        self.repository = WorkflowRepository()
        self.api.database = self.repository
        self.api.change_workflows.repository = self.repository

    def test_workflow_snapshots_and_events_persist_and_restore(self):
        payload = {
            "request_id": str(uuid4()), "actor_id": "operator-a", "action": "vm.resize",
            "target": "lab-vm", "environment": "lab", "mode": "mutate",
            "capabilities": ["vm.resize"], "reason": "test only", "tenant_id": "tenant-a",
        }
        status, created = self.api.dispatch("POST", "/v1/change-workflows", payload)
        self.assertEqual(status, 201)
        workflow_id = created["workflow_id"]
        self.assertEqual(created["state"], "approval_pending")
        self.assertEqual(self.repository.events[-1], ("change.workflow.started", "approval_pending"))
        persisted = self.repository.rows[workflow_id]
        self.assertFalse(persisted.get("execution_permitted", False))
        approval = ApprovalRecord(
            approval_id="approval-a", request_id=payload["request_id"], approver_id="operator-a",
            tenant_id="tenant-a", signature_verified=True,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            plan_id=workflow_id,
        )
        self.api.store.approvals[approval.approval_id] = approval
        approved = self.api.change_workflows.approve(
            workflow_id=UUID(workflow_id), tenant_id="tenant-a", approval_id=approval.approval_id,
        )
        self.assertEqual(approved["state"], "approved")
        self.assertEqual(self.repository.rows[workflow_id]["workflow"]["state"], "approved")
        self.assertEqual(self.repository.events[-1], ("change.workflow.approval_recorded", "approved"))

        restored = LocalControlPlaneApi()
        restored.store.tenants.update(self.api.store.tenants)
        restored.store.identities.update(self.api.store.identities)
        restored.store.assets.update(self.api.store.assets)
        restored.store.requests.update(self.api.store.requests)
        restored.database = self.repository
        restored.change_workflows.restore_persisted(
            "tenant-a", [row["plan"] for row in self.repository.persisted_change_workflows("tenant-a")]
        )
        described = restored.change_workflows.describe(workflow_id=UUID(workflow_id), tenant_id="tenant-a")
        self.assertEqual(described["state"], "approved")
        self.assertEqual(described["request_id"], payload["request_id"])


if __name__ == "__main__":
    unittest.main()
