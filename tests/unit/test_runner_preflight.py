from __future__ import annotations

import datetime as dt
import hashlib
import json
from copy import deepcopy
import unittest
from uuid import uuid4

from control_plane_core.runner_preflight import RunnerPreflight


class GrantVerifier:
    def verify(self, envelope, *, expected_claims):
        self.expected_claims = expected_claims
        if envelope != {"test": "signed-grant"}:
            raise PermissionError("invalid grant")
        return ({"expires_at": self.expires_at, "max_runtime_seconds": 30}, "d" * 64)


class LeaseSource:
    def __init__(self, lease):
        self.lease = deepcopy(lease)
        self.request = None

    def get_current_execution_lease(self, *, task_id, runner_id):
        self.request = (task_id, runner_id)
        return dict(self.lease)


class RunnerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "schema_version": "a2z-task-plan-v1",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vm-lab-1"], "environment": "lab",
            "preconditions": {
                "power_state": "powered_off",
                "description": "A2Z-Control-Plane-Unlabeled",
            },
            "desired_state": {"description": "A2Z-Control-Plane-Demo"},
            "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
            "max_runtime_seconds": 30,
        }
        canonical = json.dumps(self.plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.token = "test-lease-token-never-returned"
        approval_id = str(uuid4())
        self.lease = {
            "task_id": str(uuid4()), "tenant_id": "lab", "target_id": "vm-lab-1",
            "operation_id": self.plan["operation_id"], "environment": "lab",
            "plan_digest": hashlib.sha256(canonical).hexdigest(),
            "authorization_mode": "operator_approval", "authorization_id": approval_id,
            "approval_id": approval_id, "policy_digest": None, "impact_assessment_digest": None,
            "lease_generation": 4, "runner_id": "runner-lab-1", "lease_token": self.token,
            "status": "leased", "lease_stage": "execution",
            "lease_until": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)).isoformat(),
            "plan": self.plan,
        }
        self.source = LeaseSource(self.lease)
        self.verifier = GrantVerifier()
        self.verifier.expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)).isoformat()
        self.gate = RunnerPreflight(lease_source=self.source, grant_verifier=self.verifier)

    def test_preflight_derives_grant_claims_from_authenticated_live_lease(self):
        checked = self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                                   authenticated_runner_id="runner-lab-1")
        self.assertEqual(self.source.request, (self.lease["task_id"], "runner-lab-1"))
        self.assertEqual(self.verifier.expected_claims["lease_generation"], 4)
        self.assertEqual(self.verifier.expected_claims["lease_token_sha256"], hashlib.sha256(self.token.encode()).hexdigest())
        self.assertEqual(checked.plan_digest, self.lease["plan_digest"])
        self.assertFalse(hasattr(checked, "lease_token"))

    def test_rejects_wrong_runner_expired_lease_and_non_execution_state(self):
        cases = [
            ({"runner_id": "other-runner"}, "authenticated runner scope"),
            ({"lease_until": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()}, "expired"),
            ({"status": "queued"}, "active execution lease"),
            ({"lease_stage": "policy"}, "active execution lease"),
        ]
        for changes, reason in cases:
            with self.subTest(changes=changes):
                self.source.lease.update(changes)
                with self.assertRaisesRegex(PermissionError, reason):
                    self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                                     authenticated_runner_id="runner-lab-1")
                self.source.lease.update({key: value for key, value in self.lease.items()})

    def test_rejects_mutated_plan_scope_or_code_owned_operation_expansion(self):
        self.source.lease["plan"]["desired_state"]["description"] = "not-approved"
        with self.assertRaisesRegex(PermissionError, "plan digest"):
            self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                             authenticated_runner_id="runner-lab-1")

    def test_rejects_unknown_operation_and_invalid_plan_runtime(self):
        self.source.lease["operation_id"] = "virtualbox.vm.arbitrary_command"
        self.source.lease["plan"]["operation_id"] = "virtualbox.vm.arbitrary_command"
        self.source.lease["plan_digest"] = hashlib.sha256(json.dumps(
            self.source.lease["plan"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest()
        with self.assertRaisesRegex(PermissionError, "code-owned runner catalog"):
            self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                             authenticated_runner_id="runner-lab-1")
        self.source.lease = deepcopy(self.lease)
        self.source.lease["plan"]["max_runtime_seconds"] = True
        self.source.lease["plan_digest"] = hashlib.sha256(json.dumps(
            self.source.lease["plan"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest()
        with self.assertRaisesRegex(PermissionError, "invalid schema or runtime"):
            self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                             authenticated_runner_id="runner-lab-1")

    def test_rejects_grant_that_outlives_lease_or_exceeds_plan_runtime(self):
        self.verifier.expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2)).isoformat()
        with self.assertRaisesRegex(PermissionError, "outlives"):
            self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                             authenticated_runner_id="runner-lab-1")
        self.verifier.expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=20)).isoformat()
        self.verifier.verify = lambda envelope, *, expected_claims: ({
            "expires_at": self.verifier.expires_at, "max_runtime_seconds": 31,
        }, "d" * 64)
        with self.assertRaisesRegex(PermissionError, "exceeds the task plan"):
            self.gate.verify({"test": "signed-grant"}, task_id=self.lease["task_id"],
                             authenticated_runner_id="runner-lab-1")


if __name__ == "__main__":
    unittest.main()
