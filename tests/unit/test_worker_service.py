from __future__ import annotations

import unittest
import tempfile
import stat
from types import SimpleNamespace
from pathlib import Path
from uuid import uuid4

from control_plane_core.worker_service import GovernedVirtualBoxWorker
from control_plane_core.receipt_outbox import RunnerReceiptOutbox


class FakeTransport:
    runner_id = "runner-lab-1"

    def __init__(self):
        self.task_id = str(uuid4())
        self.token = "lease-token-fixture"
        self.digest = "a" * 64
        self.calls = []
        self.ready = [{
            "task_id": self.task_id, "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vm-lab-1"], "environment": "lab",
            "plan_digest": self.digest,
        }]
        self.fail_receipt_once = False
        self.fail_receipt_permission_once = False

    def list_ready_tasks(self):
        self.calls.append("list")
        return list(self.ready)

    def claim(self, *, task_id):
        self.calls.append(("claim", task_id))
        self.ready = []
        return {
            "task_id": task_id, "tenant_id": "lab-tenant", "runner_id": self.runner_id,
            "status": "leased", "lease_generation": 2, "lease_token": self.token,
            "plan_digest": self.digest, "environment": "lab",
        }

    def issue_grant(self, *, task_id, lease_token):
        self.calls.append(("grant", task_id, lease_token))
        return {"grant": {"signed": "grant"}, "grant_sha256": "b" * 64, "execution_permitted": False}

    def submit_attestation(self, *, task_id, signed_attestation, lease_token):
        self.calls.append(("receipt", task_id, signed_attestation, lease_token))
        if self.fail_receipt_permission_once:
            raise PermissionError("lease expired before receipt delivery")
        if self.fail_receipt_once:
            self.fail_receipt_once = False
            raise ConnectionError("response unavailable")
        return {
            "attestation_sha256": "c" * 64,
            "receipt_id": signed_attestation["attestation"]["receipt_id"],
            "status": "verified_evidence_only", "execution_permitted": False,
            "postcondition_verified": False,
        }

    def reconcile_attestation(self, *, task_id, signed_attestation):
        self.calls.append(("reconcile", task_id, signed_attestation))
        return {
            "attestation_sha256": "c" * 64,
            "receipt_id": signed_attestation["attestation"]["receipt_id"],
            "status": "verified_evidence_only", "execution_permitted": False,
            "postcondition_verified": False, "task_status": "verification",
        }


class FakeSigner:
    def sign(self, attestation):
        self.attestation = attestation
        return {"attestation": attestation, "signature": {"test": "signed"}}


class GovernedVirtualBoxWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-worker-outbox-")
        self.transport = FakeTransport()
        self.signer = FakeSigner()
        self.outbox = RunnerReceiptOutbox(Path(self.temp.name) / "receipts.sqlite3")
        self.adapter = SimpleNamespace(
            execute=self.execute_adapter,
        )
        self.worker = GovernedVirtualBoxWorker(
            transport=self.transport, adapter=self.adapter, receipt_signer=self.signer,
            outbox=self.outbox,
        )

    def tearDown(self):
        self.outbox.close()
        self.temp.cleanup()

    def execute_adapter(self, grant, *, task_id, authenticated_runner_id):
        self.transport.calls.append(("execute", task_id, authenticated_runner_id, grant))
        return SimpleNamespace(
            task_id=task_id, target_id="vm-lab-1",
            operation_id="virtualbox.vm.set_demo_description",
            before={"description": "old"}, after={"description": "new"},
            rollback_attempted=False,
        )

    def test_processes_one_claimed_task_and_submits_signed_evidence_only(self):
        result = self.worker.process_next()
        self.assertEqual(result["status"], "awaiting_independent_verification")
        self.assertFalse(result["execution_permitted"])
        self.assertFalse(result["postcondition_verified"])
        self.assertEqual(
            [call if isinstance(call, str) else call[0] for call in self.transport.calls],
            ["list", "claim", "grant", "execute", "receipt"],
        )
        self.assertEqual(self.signer.attestation["runner_id"], self.transport.runner_id)
        self.assertEqual(self.signer.attestation["lease_generation"], 2)
        self.assertEqual(self.signer.attestation["network_calls"], 0)
        self.assertEqual(self.outbox.pending(), [])

    def test_refuses_claim_mismatch_before_adapter_invocation(self):
        self.transport.claim = lambda *, task_id: {
            "task_id": task_id, "tenant_id": "lab-tenant", "runner_id": "another-runner",
            "status": "leased", "lease_generation": 2, "lease_token": self.transport.token,
            "plan_digest": self.transport.digest, "environment": "lab",
        }
        with self.assertRaisesRegex(PermissionError, "does not match"):
            self.worker.process_next()
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "execute" for call in self.transport.calls))

    def test_ignores_unsupported_queued_operation_without_claiming(self):
        self.transport.list_ready_tasks = lambda: [{
            "task_id": str(uuid4()), "operation_id": "shell.exec", "target_ids": ["vm-lab-1"],
            "environment": "lab", "plan_digest": "a" * 64,
        }]
        result = self.worker.process_next()
        self.assertEqual(result["status"], "no_supported_ready_task")
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "claim" for call in self.transport.calls))

    def test_response_loss_keeps_signed_receipt_and_replays_without_reexecuting(self):
        self.transport.fail_receipt_once = True
        first = self.worker.process_next()
        self.assertEqual(first["status"], "pending_receipt_delivery_deferred")
        pending = self.outbox.pending()
        self.assertEqual(len(pending), 1)
        saved_envelope = pending[0]["envelope"]
        self.assertEqual(stat.S_IMODE(self.outbox.path.stat().st_mode), 0o600)

        # Simulate process restart: the same signed receipt and lease token must
        # survive in the local durable outbox without rerunning the adapter.
        outbox_path = self.outbox.path
        self.outbox.close()
        self.outbox = RunnerReceiptOutbox(outbox_path)
        self.worker = GovernedVirtualBoxWorker(
            transport=self.transport, adapter=self.adapter,
            receipt_signer=self.signer, outbox=self.outbox,
        )

        second = self.worker.process_next()
        self.assertEqual(second["status"], "no_supported_ready_task")
        self.assertEqual(self.outbox.pending(), [])
        submissions = [call for call in self.transport.calls if isinstance(call, tuple) and call[0] == "receipt"]
        self.assertEqual(len(submissions), 2)
        self.assertEqual(submissions[0][2], saved_envelope)
        self.assertEqual(submissions[1][2], saved_envelope)
        self.assertEqual(sum(1 for call in self.transport.calls if isinstance(call, tuple) and call[0] == "execute"), 1)

    def test_expired_lease_uses_exact_receipt_reconciliation_without_rerunning_mutation(self):
        self.transport.fail_receipt_permission_once = True
        first = self.worker.process_next()
        self.assertEqual(first["status"], "pending_receipt_reconciliation_required")
        saved = self.outbox.pending()[0]["envelope"]
        self.assertEqual(sum(1 for call in self.transport.calls if isinstance(call, tuple) and call[0] == "execute"), 1)

        second = self.worker.process_next()
        self.assertEqual(second["status"], "no_supported_ready_task")
        self.assertEqual(self.outbox.pending(), [])
        reconciliation = next(call for call in self.transport.calls if isinstance(call, tuple) and call[0] == "reconcile")
        self.assertEqual(reconciliation[2], saved)
        self.assertEqual(sum(1 for call in self.transport.calls if isinstance(call, tuple) and call[0] == "execute"), 1)


if __name__ == "__main__":
    unittest.main()
