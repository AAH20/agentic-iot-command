from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from control_plane_core.postcondition_observer import IndependentVirtualBoxPostconditionObserver
from control_plane_core.postcondition_outbox import PostconditionAttestationOutbox


class FakeJournal:
    def __init__(self):
        self.tenant_id = "lab-tenant"
        self.task_id = str(uuid4())
        self.target_id = str(uuid4())
        self.plan = {
            "schema_version": "a2z-task-plan-v1",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": [self.target_id], "environment": "lab",
            "preconditions": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Unlabeled"},
            "desired_state": {"description": "A2Z-Control-Plane-Demo"},
            "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
            "max_runtime_seconds": 30,
        }
        canonical = json.dumps(self.plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.plan_digest = hashlib.sha256(canonical).hexdigest()
        self.receipt_id = str(uuid4())

    def get_postcondition_candidate(self, *, task_id, tenant_id):
        self.request = (task_id, tenant_id)
        return {
            "task_id": self.task_id, "tenant_id": "lab-tenant", "target_id": self.target_id,
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "plan_digest": self.plan_digest, "lease_generation": 4, "plan": self.plan,
            "runner_attestation": {"attestation": {
                "task_id": self.task_id, "tenant_id": "lab-tenant", "target_id": self.target_id,
                "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
                "plan_digest": self.plan_digest, "lease_generation": 4,
                "receipt_id": self.receipt_id, "outcome": "succeeded",
            }, "signature": {"algorithm": "ed25519", "key_id": "runner-key", "signature_base64": "x"}},
            "runner_attestation_sha256": "a" * 64,
        }


class FakeSigner:
    def sign(self, attestation):
        self.attestation = attestation
        return {"attestation": attestation, "signature": {
            "algorithm": "ed25519", "key_id": "observer-key", "signature_base64": "c2ln",
        }}


class PostconditionObserverTests(unittest.TestCase):
    def setUp(self):
        self.journal = FakeJournal()
        self.signer = FakeSigner()
        self.calls = []

        def command_runner(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout='VMState="poweroff"\ndescription="A2Z-Control-Plane-Demo"\n', stderr="")

        self.observer = IndependentVirtualBoxPostconditionObserver(
            journal=self.journal, verifier_id="observer-lab-1", signer=self.signer,
            vboxmanage="/usr/bin/openssl", command_runner=command_runner,
        )

    def test_observes_only_exact_read_only_task_and_signs_journal_bound_state(self):
        envelope = self.observer.attest_task(task_id=self.journal.task_id, tenant_id="lab-tenant")
        self.assertEqual(self.journal.request, (self.journal.task_id, "lab-tenant"))
        self.assertEqual(len(self.calls), 1)
        argv, kwargs = self.calls[0]
        self.assertEqual(argv, ["/usr/bin/openssl", "showvminfo", self.journal.target_id, "--machinereadable"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(envelope["attestation"]["receipt_id"], self.journal.receipt_id)
        self.assertEqual(envelope["attestation"]["observed_state"], {
            "power_state": "powered_off", "description": "A2Z-Control-Plane-Demo",
        })
        self.assertEqual(self.signer.attestation["verifier_id"], "observer-lab-1")

    def test_refuses_runner_reported_failure_before_observing(self):
        candidate = self.journal.get_postcondition_candidate(task_id=self.journal.task_id, tenant_id="lab-tenant")
        candidate["runner_attestation"]["attestation"]["outcome"] = "unknown"
        self.journal.get_postcondition_candidate = lambda **kwargs: candidate
        with self.assertRaisesRegex(PermissionError, "failed or unknown"):
            self.observer.attest_task(task_id=self.journal.task_id, tenant_id="lab-tenant")
        self.assertEqual(self.calls, [])

    def test_refuses_tampered_task_plan_digest_before_observing(self):
        candidate = self.journal.get_postcondition_candidate(task_id=self.journal.task_id, tenant_id="lab-tenant")
        candidate["plan"]["desired_state"]["description"] = "tampered"
        self.journal.get_postcondition_candidate = lambda **kwargs: candidate
        with self.assertRaisesRegex(PermissionError, "journal plan"):
            self.observer.attest_task(task_id=self.journal.task_id, tenant_id="lab-tenant")
        self.assertEqual(self.calls, [])

    def test_signed_observation_is_durably_spooled_and_exactly_replayed_after_response_loss(self):
        class JournalClient:
            def __init__(self, source):
                self.source = source
                self.tenant_id = source.tenant_id
                self.submissions = []
                self.fail_once = True

            def get_postcondition_candidate(self, **kwargs):
                return self.source.get_postcondition_candidate(**kwargs)

            def record_postcondition_attestation(self, **kwargs):
                self.submissions.append(kwargs["signed_attestation"])
                if self.fail_once:
                    self.fail_once = False
                    raise ConnectionError("simulated lost response")
                return {"task_id": kwargs["task_id"], "status": "completed", "verified": True}

            def list_postcondition_candidates(self, *, limit):
                self.list_limit = limit
                return []

        client = JournalClient(self.journal)
        self.observer.journal = client
        with tempfile.TemporaryDirectory(prefix="a2z-postcondition-outbox-") as directory:
            outbox_path = Path(directory) / "attestations.sqlite3"
            outbox = PostconditionAttestationOutbox(outbox_path)
            try:
                with self.assertRaisesRegex(ConnectionError, "lost response"):
                    self.observer.attest_and_submit(
                        task_id=self.journal.task_id, tenant_id="lab-tenant", outbox=outbox,
                    )
                pending = outbox.pending_for_task(task_id=self.journal.task_id)
                self.assertIsNotNone(pending)
                stored_envelope = pending["envelope"]
                outbox.close()

                outbox = PostconditionAttestationOutbox(outbox_path)
                results = self.observer.run_once(outbox=outbox, limit=1)
                self.assertEqual(results[0]["status"], "completed")
                self.assertEqual(client.list_limit, 1)
                self.assertEqual(client.submissions, [stored_envelope, stored_envelope])
                self.assertEqual(outbox.pending(), [])
                self.assertEqual(len(self.calls), 1, "retry must not repeat VirtualBox observation")
            finally:
                outbox.close()

    def test_run_once_polls_bounded_ready_metadata_then_observes_and_submits(self):
        class JournalClient:
            tenant_id = "lab-tenant"

            def __init__(self, source):
                self.source = source
                self.submitted = []

            def list_postcondition_candidates(self, *, limit):
                self.limit = limit
                return [{
                    "task_id": self.source.task_id, "target_id": self.source.target_id,
                    "operation_id": "virtualbox.vm.set_demo_description",
                    "environment": "lab", "plan_digest": self.source.plan_digest,
                }]

            def get_postcondition_candidate(self, **kwargs):
                return self.source.get_postcondition_candidate(**kwargs)

            def record_postcondition_attestation(self, **kwargs):
                self.submitted.append(kwargs["signed_attestation"])
                return {"task_id": kwargs["task_id"], "status": "completed", "verified": True}

        client = JournalClient(self.journal)
        self.observer.journal = client
        with tempfile.TemporaryDirectory(prefix="a2z-postcondition-ready-") as directory:
            outbox = PostconditionAttestationOutbox(Path(directory) / "outbox.sqlite3")
            try:
                results = self.observer.run_once(outbox=outbox, limit=3)
                self.assertEqual(client.limit, 3)
                self.assertEqual(len(client.submitted), 1)
                self.assertEqual(results[0]["status"], "completed")
                self.assertEqual(outbox.pending(), [])
                self.assertEqual(len(self.calls), 1)
            finally:
                outbox.close()


if __name__ == "__main__":
    unittest.main()
