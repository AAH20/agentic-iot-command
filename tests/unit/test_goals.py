from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from control_plane_core.impact_assessments import VerifiedImpactAssessment, impact_assessment_digest
from control_plane_core.goals import DurableGoalStore, _canonical


def make_plan(operation_id, target_ids, environment, *, desired_state=None):
    return {
        "schema_version": "a2z-task-plan-v1",
        "operation_id": operation_id,
        "target_ids": list(target_ids),
        "environment": environment,
        "preconditions": {"inventory_fresh": True},
        "desired_state": desired_state or {"operation_complete": True},
        "rollback": {"strategy": "operator_review"},
        "max_runtime_seconds": 300,
    }


class DurableGoalStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-goals-")
        self.path = Path(self.temp.name) / "goals.sqlite3"
        self.store = DurableGoalStore(self.path)
        self.goal = self.store.submit_goal(
            tenant_id="lab-tenant",
            requested_by="operator-1",
            idempotency_key="goal-request-001",
            objective="Keep the approved lab virtualization fleet healthy",
            guardrails={"profile_id": "lab-routines", "critical_decisions": "operator"},
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_ready_execution_task_listing_is_exactly_scoped_and_metadata_only(self):
        def queued(target, environment="lab"):
            plan = make_plan(
                "virtualbox.vm.set_demo_description", (target,), environment,
                desired_state={"description": "A2Z-Control-Plane-Demo"},
            )
            task = self.store.add_task(
                goal_id=self.goal.goal_id, tenant_id="lab-tenant",
                operation_id="virtualbox.vm.set_demo_description", target_ids=(target,),
                environment=environment, plan=plan,
            )
            self.store._db.execute("UPDATE tasks SET status='queued' WHERE task_id=?", (task["task_id"],))
            return task

        allowed = queued("vm-lab-1")
        queued("vm-other-1")
        queued("vm-lab-1", "staging")
        ready = self.store.list_ready_execution_tasks(
            tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            environments=frozenset({"lab"}), limit=10,
        )
        self.assertEqual([item["task_id"] for item in ready], [allowed["task_id"]])
        self.assertEqual(set(ready[0]), {
            "task_id", "operation_id", "target_ids", "environment", "plan_digest", "created_at",
        })
        with self.assertRaisesRegex(PermissionError, "forbidden environment"):
            self.store.list_ready_execution_tasks(
                tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
                operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
                environments=frozenset({"production"}),
            )

    def _make_auto_eligible_task(self, *, window_open=True):
        now = datetime.now(timezone.utc)
        issued = now - timedelta(hours=1)
        ends = now + timedelta(minutes=20) if window_open else now - timedelta(minutes=1)
        profile_record = {
            "profile": {
                "schema_version": "autonomy-profile-v1", "profile_id": "lab-profile",
                "tenant_id": "lab-tenant", "enabled": True,
                "issued_at": issued.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
                "max_concurrency": 1, "max_total_targets": 1,
                "max_affected_resources": 1, "max_estimated_cost_microusd": 0,
                "rules": [{
                    "action_id": "virtualbox.vm.set_demo_description",
                    "target_ids": ["vm-lab-1"], "environments": ["lab"],
                    "max_targets_per_run": 1, "max_batch_size": 1,
                    "max_affected_resources": 1, "max_estimated_cost_microusd": 0,
                    "enabled": True,
                }],
                "maintenance_windows": [{
                    "window_id": "demo-window",
                    "action_id": "virtualbox.vm.set_demo_description",
                    "target_ids": ["vm-lab-1"], "environments": ["lab"],
                    "starts_at": (now - timedelta(minutes=10)).isoformat(),
                    "ends_at": ends.isoformat(),
                }],
                "denied_actions": [],
                "defaults": {
                    "unknown_action": "deny", "non_allowlisted_action": "approval_required",
                    "high_impact_action": "approval_required", "production_action": "approval_required",
                    "regulated_action": "deny",
                },
            },
            "signature": {"algorithm": "ed25519", "key_id": "policy-test", "signature_base64": "c2ln"},
        }
        assessment_record = {
            "assessment": {
                "schema_version": "a2z-impact-assessment-v1",
                "assessment_id": "00000000-0000-4000-8000-000000000111",
                "tenant_id": "lab-tenant", "task_id": "",
                "operation_id": "virtualbox.vm.set_demo_description",
                "target_ids": ["vm-lab-1"], "environment": "lab", "plan_digest": "",
                "affected_resource_count": 1, "estimated_cost_microusd": 0,
                "source_id": "signed-test-estimator",
                "generated_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
            },
            "signature": {"algorithm": "ed25519", "key_id": "estimator-test", "signature_base64": "c2ln"},
        }
        goal = self.store.submit_goal(
            tenant_id="lab-tenant", requested_by="operator-1",
            idempotency_key=f"auto-queue-{window_open}",
            objective="Apply the fixed metadata label to the disposable VM",
            guardrails={
                "autonomy_enabled": True, "allowed_environments": ["lab"],
                "allowed_targets": ["vm-lab-1"], "profile_id": "lab-profile",
            },
        )
        plan = {
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
        task = self.store.add_task(
            goal_id=goal.goal_id, tenant_id="lab-tenant",
            operation_id=plan["operation_id"], target_ids=("vm-lab-1",),
            environment="lab", plan=plan,
        )
        assessment_record["assessment"]["task_id"] = task["task_id"]
        assessment_record["assessment"]["plan_digest"] = task["plan_digest"]
        assessment_digest = impact_assessment_digest(assessment_record)
        policy_digest = "b" * 64
        claim = self.store.claim_policy_task(
            task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test",
        )

        class ProfileVerifier:
            revoked = False

            def verify(inner_self, envelope):
                if inner_self.revoked:
                    raise PermissionError("autonomy signing key revoked")
                return policy_digest

        class EstimatorVerifier:
            def verify(inner_self, envelope, *, expected):
                return VerifiedImpactAssessment(
                    tenant_id=expected["tenant_id"], task_id=expected["task_id"],
                    operation_id=expected["operation_id"], target_ids=expected["target_ids"],
                    environment=expected["environment"], plan_digest=expected["plan_digest"],
                    affected_resource_count=1, estimated_cost_microusd=0,
                    source_id="signed-test-estimator", assessment_digest=assessment_digest,
                    expires_at=now + timedelta(minutes=5),
                )

        profile_verifier, estimator_verifier = ProfileVerifier(), EstimatorVerifier()
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
            disposition="auto_eligible", reasons=("signed_bounded_routine_rule_matches",),
            policy_digest=policy_digest, impact_assessment_digest=assessment_digest,
            impact_assessment_record=assessment_record,
            autonomy_profile_record=profile_record, autonomy_profile_verifier=profile_verifier,
        )
        return task, profile_verifier, estimator_verifier

    def test_idempotent_goal_submission_and_tenant_isolation(self):
        repeated = self.store.submit_goal(
            tenant_id="lab-tenant", requested_by="operator-1", idempotency_key="goal-request-001",
            objective="Keep the approved lab virtualization fleet healthy",
            guardrails={"profile_id": "lab-routines", "critical_decisions": "operator"},
        )
        self.assertFalse(repeated.created)
        self.assertEqual(repeated.goal_id, self.goal.goal_id)
        with self.assertRaises(ValueError):
            self.store.submit_goal(
                tenant_id="lab-tenant", requested_by="operator-1", idempotency_key="goal-request-001",
                objective="different replay body", guardrails={},
            )
        self.assertEqual(self.store.events(goal_id=self.goal.goal_id, tenant_id="other-tenant"), ())

    def test_auto_eligible_decision_requires_and_retains_matching_signed_profile(self):
        plan = make_plan(
            "virtualbox.vm.set_demo_description", ("vm-lab-1",), "lab",
            desired_state={"description": "A2Z-Control-Plane-Demo"},
        )
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant",
            operation_id="virtualbox.vm.set_demo_description",
            target_ids=("vm-lab-1",), environment="lab", plan=plan,
        )
        claim = self.store.claim_policy_task(
            task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test",
        )
        profile_record = {
            "profile": {"tenant_id": "lab-tenant", "enabled": True},
            "signature": {"algorithm": "ed25519", "key_id": "policy-test", "signature_base64": "c2ln"},
        }

        class ProfileVerifier:
            def verify(inner_self, envelope):
                inner_self.envelope = envelope
                return "b" * 64

        verifier = ProfileVerifier()
        with self.assertRaisesRegex(PermissionError, "signed autonomy profile"):
            self.store.record_decision(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
                disposition="auto_eligible", reasons=("test",), policy_digest="b" * 64,
            )
        wrong_tenant = {"profile": {"tenant_id": "other", "enabled": True}, "signature": profile_record["signature"]}
        with self.assertRaisesRegex(PermissionError, "tenant"):
            self.store.record_decision(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
                disposition="auto_eligible", reasons=("test",), policy_digest="b" * 64,
                autonomy_profile_record=wrong_tenant, autonomy_profile_verifier=verifier,
            )
        decided = self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
            disposition="auto_eligible", reasons=("test",), policy_digest="b" * 64,
            autonomy_profile_record=profile_record, autonomy_profile_verifier=verifier,
        )
        self.assertEqual(decided["status"], "auto_eligible")
        self.assertEqual(decided["decision"]["autonomy_profile"], profile_record)
        self.assertFalse(decided["execution_permitted"])

    def test_autonomous_queue_revalidates_policy_and_estimate_without_human_approval(self):
        task, profile_verifier, estimator_verifier = self._make_auto_eligible_task()
        queued = self.store.queue_autonomous_task(
            task_id=task["task_id"], tenant_id="lab-tenant",
            autonomy_profile_verifier=profile_verifier, impact_verifier=estimator_verifier,
        )
        self.assertEqual(queued["status"], "queued")
        self.assertIsNone(queued["approval_ref"])
        self.assertEqual(queued["decision"]["authorization_mode"], "standing_policy")
        self.assertFalse(queued["execution_permitted"])
        self.assertTrue(self.store.verify_events(
            goal_id=task["goal_id"], tenant_id="lab-tenant",
        )["events"] >= 5)
        with self.assertRaisesRegex(PermissionError, "trusted verifiers"):
            self.store.claim_execution_lease(
                task_id=task["task_id"], tenant_id="lab-tenant",
                worker_id="runner-lab-1", approval_verifier=None,
            )
        lease = self.store.claim_execution_lease(
            task_id=task["task_id"], tenant_id="lab-tenant", worker_id="runner-lab-1",
            autonomy_profile_verifier=profile_verifier, impact_verifier=estimator_verifier,
        )
        self.assertEqual(lease["status"], "leased")
        self.assertIsNone(lease["approval_ref"])
        self.assertEqual(lease["decision"]["authorization_mode"], "standing_policy")

        class GrantSigner:
            def sign(self, grant):
                return {"grant": grant, "signature": {"algorithm": "ed25519", "key_id": "test", "signature_base64": "AA=="}}

        class GrantVerifier:
            def verify(self, envelope, *, expected_claims):
                self.expected_claims = expected_claims
                grant = envelope["grant"]
                if any(grant.get(key) != value for key, value in expected_claims.items()):
                    raise PermissionError("grant claims mismatch")
                return grant, "d" * 64

        class OpenControl:
            def assert_enabled(self):
                return "e" * 64

        grant_verifier = GrantVerifier()
        profile_verifier.revoked = True
        with self.assertRaisesRegex(PermissionError, "revoked"):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                autonomy_profile_verifier=profile_verifier, impact_verifier=estimator_verifier,
                grant_signer=GrantSigner(), grant_verifier=grant_verifier,
                execution_control=OpenControl(),
            )
        profile_verifier.revoked = False
        issued = self.store.issue_execution_grant(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            autonomy_profile_verifier=profile_verifier, impact_verifier=estimator_verifier,
            grant_signer=GrantSigner(), grant_verifier=grant_verifier,
            execution_control=OpenControl(),
        )
        grant = issued["grant"]["grant"]
        self.assertEqual(grant["authorization_mode"], "standing_policy")
        self.assertEqual(grant["authorization_id"], lease["decision"]["autonomous_queue"]["authorization_id"])
        self.assertIsNone(grant["approval_id"])
        self.assertEqual(grant["policy_digest"], queued["decision"]["autonomous_queue"]["policy_digest"])
        self.assertEqual(grant["impact_assessment_digest"], queued["decision"]["autonomous_queue"]["impact_assessment_digest"])
        profile_verifier.revoked = True
        with self.assertRaisesRegex(PermissionError, "revoked"):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                authenticated_runner_id="runner-lab-1", autonomy_profile_verifier=profile_verifier,
                impact_verifier=estimator_verifier, grant_verifier=grant_verifier,
                execution_control=OpenControl(),
            )
        consumed_before_retry = self.store._db.execute(
            "SELECT consumed_at FROM execution_grants WHERE task_id=?", (task["task_id"],),
        ).fetchone()["consumed_at"]
        self.assertIsNone(consumed_before_retry)
        profile_verifier.revoked = False
        running = self.store.start_leased_task(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            authenticated_runner_id="runner-lab-1", autonomy_profile_verifier=profile_verifier,
            impact_verifier=estimator_verifier, grant_verifier=grant_verifier,
            execution_control=OpenControl(),
        )
        self.assertEqual(running["status"], "running")
        self.assertTrue(running["permit_consumed"])

    def test_autonomous_queue_rejects_closed_or_expired_signed_window(self):
        task, profile_verifier, estimator_verifier = self._make_auto_eligible_task(window_open=False)
        with self.assertRaisesRegex(PermissionError, "window_not_open"):
            self.store.queue_autonomous_task(
                task_id=task["task_id"], tenant_id="lab-tenant",
                autonomy_profile_verifier=profile_verifier, impact_verifier=estimator_verifier,
            )
        self.assertEqual(
            self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"],
            "auto_eligible",
        )

    def test_task_plan_is_retained_and_digest_is_server_derived(self):
        plan = make_plan("virtualbox.vm.refresh_inventory", ("vbox-host-1",), "lab")
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.refresh_inventory",
            target_ids=("vbox-host-1",), environment="lab", plan=plan,
        )
        expected_digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        self.assertEqual(task["plan_digest"], expected_digest)
        self.assertEqual(task["plan"], plan)
        mismatched = make_plan("virtualbox.vm.refresh_inventory", ("other-vm",), "lab")
        with self.assertRaisesRegex(ValueError, "do not exactly match"):
            self.store.add_task(
                goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.refresh_inventory",
                target_ids=("vbox-host-1",), environment="lab", plan=mismatched,
            )
        with_secret = make_plan("virtualbox.vm.refresh_inventory", ("vbox-host-1",), "lab")
        with_secret["desired_state"]["password"] = "must-not-persist"
        with self.assertRaisesRegex(PermissionError, "must not contain secret"):
            self.store.add_task(
                goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.refresh_inventory",
                target_ids=("vbox-host-1",), environment="lab", plan=with_secret,
            )

    def test_tampered_persisted_plan_cannot_be_approved_or_leased(self):
        plan = make_plan("virtualbox.vm.start", ("vm-lab-1",), "lab", desired_state={"power_state": "running"})
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vm-lab-1",), environment="lab", plan=plan,
        )
        changed = make_plan("virtualbox.vm.start", ("vm-lab-1",), "lab", desired_state={"power_state": "poweroff"})
        self.store._db.execute(
            "UPDATE tasks SET plan_json=? WHERE task_id=?",
            (json.dumps(changed, sort_keys=True, separators=(",", ":")), task["task_id"]),
        )
        claim = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )

        class MustNotVerify:
            def verify(self, signed_record, *, expected_scope):
                raise AssertionError("approval verifier must not run for a corrupted plan")

        with self.assertRaisesRegex(PermissionError, "digest verification failed"):
            self.store.queue_task(
                task_id=task["task_id"], tenant_id="lab-tenant", signed_approval={},
                approval_verifier=MustNotVerify(),
            )

    def test_typed_task_and_policy_journal_survive_restart(self):
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.refresh_inventory",
            target_ids=("vbox-host-1",), environment="lab",
            plan=make_plan("virtualbox.vm.refresh_inventory", ("vbox-host-1",), "lab"),
        )
        claimed = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claimed["lease_token"], disposition="approval_required",
            reasons=("signed_bounded_routine_rule_matches",), policy_digest="b" * 64,
        )
        task_id = task["task_id"]
        self.store.close()
        self.store = DurableGoalStore(self.path)
        persisted = self.store.get_task(task_id=task_id, tenant_id="lab-tenant")
        self.assertEqual(persisted["status"], "approval_required")
        self.assertFalse(persisted["execution_permitted"])
        self.assertEqual(self.store.verify_events(goal_id=self.goal.goal_id, tenant_id="lab-tenant")["events"], 4)
        with self.assertRaises(PermissionError):
            self.store.queue_task(task_id=task_id, tenant_id="lab-tenant", signed_approval={}, approval_verifier=None)

    def test_free_form_shell_task_and_unverified_approval_cannot_be_queued(self):
        with self.assertRaises(ValueError):
            self.store.add_task(
                goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="shell.exec",
                target_ids=("host-1",), environment="lab",
                plan=make_plan("shell.exec", ("host-1",), "lab"),
            )
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vm-1",), environment="lab",
            plan=make_plan("virtualbox.vm.start", ("vm-1",), "lab"),
        )
        claimed = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claimed["lease_token"], disposition="approval_required", reasons=("high_impact",), policy_digest="")
        with self.assertRaises(PermissionError):
            self.store.queue_task(task_id=task["task_id"], tenant_id="lab-tenant", signed_approval={}, approval_verifier=None)

    def test_policy_evaluation_lease_is_exclusive_and_fenced(self):
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vbox-host-1",), environment="lab",
            plan=make_plan("virtualbox.vm.start", ("vbox-host-1",), "lab"),
        )
        claim = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="worker-a")
        self.assertNotIn("lease_token", self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant"))
        with self.assertRaises(PermissionError):
            self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="worker-b")
        with self.assertRaises(PermissionError):
            self.store.record_decision(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token="stale-token",
                disposition="approval_required", reasons=("high_impact",), policy_digest="",
            )
        result = self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )
        self.assertEqual(result["status"], "approval_required")

    def test_production_task_cannot_be_queued(self):
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="cloud.instance.restart",
            target_ids=("prod-1",), environment="production",
            plan=make_plan("cloud.instance.restart", ("prod-1",), "production"),
        )
        claimed = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claimed["lease_token"], disposition="approval_required", reasons=("production_requires_approval",), policy_digest="")
        with self.assertRaises(PermissionError):
            self.store.queue_task(task_id=task["task_id"], tenant_id="lab-tenant", signed_approval={}, approval_verifier=None)

    def test_signed_approval_binds_exact_task_and_is_single_use(self):
        from uuid import uuid4

        plan = make_plan("virtualbox.vm.start", ("vm-lab-1",), "lab", desired_state={"power_state": "running"})
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vm-lab-1",), environment="lab", plan=plan,
        )
        plan_digest = task["plan_digest"]
        claim = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=claim["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )
        approval_id = str(uuid4())

        class Verifier:
            def verify(inner_self, envelope, *, expected_scope):
                inner_self.scope = expected_scope
                return {"approval_id": approval_id, "approver_id": "operator-approver", "request_id": self.goal.goal_id}

        verifier = Verifier()
        queued = self.store.queue_task(
            task_id=task["task_id"], tenant_id="lab-tenant",
            signed_approval={"approval": {"test": "signed"}, "signature": {"test": "sig"}},
            approval_verifier=verifier,
        )
        self.assertEqual(queued["status"], "queued")
        self.assertFalse(queued["execution_permitted"])
        self.assertEqual(verifier.scope["target"], "vm-lab-1")
        self.assertEqual(verifier.scope["action"], "virtualbox.vm.start")
        self.assertEqual(verifier.scope["capabilities"], ["task.execute", f"plan.sha256:{plan_digest}"])
        self.assertEqual(queued["approval_ref"], approval_id)
        self.assertTrue(self.store.verify_events(goal_id=self.goal.goal_id, tenant_id="lab-tenant")["events"] >= 5)
        other = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vm-lab-1",), environment="lab",
            plan=make_plan("virtualbox.vm.start", ("vm-lab-1",), "lab", desired_state={"power_state": "running", "maintenance": True}),
        )
        other_lease = self.store.claim_policy_task(task_id=other["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(
            task_id=other["task_id"], tenant_id="lab-tenant", lease_token=other_lease["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )
        with self.assertRaisesRegex(PermissionError, "already consumed"):
            self.store.queue_task(
                task_id=other["task_id"], tenant_id="lab-tenant",
                signed_approval={"approval": {"test": "signed"}, "signature": {"test": "sig"}},
                approval_verifier=verifier,
            )

    def test_signed_runner_attestation_atomically_enters_verification_from_running(self):
        from uuid import uuid4

        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant",
            operation_id="virtualbox.vm.set_demo_description", target_ids=("vm-lab-1",),
            environment="lab", plan={
                "schema_version": "a2z-task-plan-v1",
                "operation_id": "virtualbox.vm.set_demo_description",
                "target_ids": ["vm-lab-1"], "environment": "lab",
                "preconditions": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Unlabeled"},
                "desired_state": {"description": "A2Z-Control-Plane-Demo"},
                "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
                "max_runtime_seconds": 30,
            },
        )
        lease_token = "runner-receipt-test-token"
        lease_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        self.store._db.execute(
            "UPDATE tasks SET status='running',lease_owner=?,lease_until=?,lease_token=?,lease_stage='execution',lease_generation=1,execution_deadline=? WHERE task_id=?",
            ("runner-lab-1", lease_until, lease_token, lease_until, task["task_id"]),
        )
        attestation = {
            "schema_version": "a2z-runner-attestation-v1", "receipt_id": str(uuid4()),
            "task_id": task["task_id"], "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": task["operation_id"], "environment": "lab",
            "plan_digest": task["plan_digest"], "lease_generation": 1,
            "runner_id": "runner-lab-1", "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(), "outcome": "succeeded",
            "changed": True, "pre_state_sha256": "a" * 64, "post_state_sha256": "b" * 64,
            "network_calls": 1, "credentials_issued": False,
        }

        class Verifier:
            def verify(inner_self, envelope, *, expected_claims):
                inner_self.expected_claims = expected_claims
                return envelope["attestation"], "c" * 64

        evidence = self.store.record_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease_token,
            signed_attestation={"attestation": attestation, "signature": {"test": "signed"}},
            verifier=Verifier(),
        )
        self.assertEqual(evidence["status"], "verified_evidence_only")
        self.assertFalse(evidence["postcondition_verified"])
        self.assertEqual(self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"], "verification")
        events = self.store.events(goal_id=self.goal.goal_id, tenant_id="lab-tenant")
        self.assertTrue(any(event["event_type"] == "task.verification_started" for event in events))
        breaker = self.store.get_circuit_breaker(
            tenant_id="lab-tenant", target_id="vm-lab-1",
            operation_id="virtualbox.vm.set_demo_description",
        )
        self.assertEqual(breaker["state"], "open")
        self.assertIn("network activity", breaker["reason"])

    def test_expired_lease_late_success_receipt_reconciles_only_to_verification(self):
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant",
            operation_id="virtualbox.vm.set_demo_description", target_ids=("vm-lab-1",),
            environment="lab", plan={
                "schema_version": "a2z-task-plan-v1",
                "operation_id": "virtualbox.vm.set_demo_description",
                "target_ids": ["vm-lab-1"], "environment": "lab",
                "preconditions": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Unlabeled"},
                "desired_state": {"description": "A2Z-Control-Plane-Demo"},
                "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
                "max_runtime_seconds": 30,
            },
        )
        now = datetime.now(timezone.utc)
        claim_time = now - timedelta(minutes=15)
        execution_time = now - timedelta(minutes=12)
        lease_until = now - timedelta(minutes=8)
        grant_expiry = now - timedelta(minutes=9)
        receipt_start = now - timedelta(minutes=11)
        receipt_end = now - timedelta(minutes=10)
        iso = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
        runner_id, token, grant_id = "runner-lab-1", "expired-lease-token", str(uuid4())
        self.store._db.execute(
            "UPDATE tasks SET status='running',lease_owner=?,lease_until=?,lease_token=?,"
            "lease_stage='execution',lease_generation=1,execution_deadline=?,updated_at=? WHERE task_id=?",
            (runner_id, iso(lease_until), token, iso(lease_until), iso(claim_time), task["task_id"]),
        )

        def append_historical_event(event_type, payload, created_at):
            row = self.store._db.execute(
                "SELECT sequence,event_hash FROM goal_events WHERE tenant_id=? AND goal_id=? "
                "ORDER BY sequence DESC LIMIT 1", ("lab-tenant", self.goal.goal_id),
            ).fetchone()
            sequence = row["sequence"] + 1 if row else 1
            previous = row["event_hash"] if row else None
            event_id = str(uuid4())
            stamp = iso(created_at)
            unsigned = {
                "sequence": sequence, "event_id": event_id, "tenant_id": "lab-tenant",
                "goal_id": self.goal.goal_id, "task_id": task["task_id"],
                "event_type": event_type, "payload": payload,
                "previous_hash": previous, "created_at": stamp,
            }
            event_hash = hashlib.sha256(_canonical(unsigned)).hexdigest()
            self.store._db.execute(
                "INSERT INTO goal_events (sequence,event_id,tenant_id,goal_id,task_id,event_type,"
                "payload_json,previous_hash,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sequence, event_id, "lab-tenant", self.goal.goal_id, task["task_id"],
                 event_type, _canonical(payload).decode(), previous, event_hash, stamp),
            )

        append_historical_event("task.execution_lease_claimed", {
            "worker_id": runner_id, "lease_generation": 1, "lease_until": iso(lease_until),
            "execution_deadline": iso(lease_until), "execution_permitted": False,
        }, claim_time)
        append_historical_event("task.execution_grant_issued", {
            "grant_id": grant_id, "grant_sha256": "d" * 64,
            "target_id": "vm-lab-1", "operation_id": task["operation_id"],
            "lease_generation": 1, "runner_id": runner_id,
            "expires_at": iso(grant_expiry), "execution_permitted": False,
        }, execution_time - timedelta(seconds=30))
        append_historical_event("task.execution_started", {
            "lease_generation": 1, "runner_id": runner_id, "grant_id": grant_id,
            "grant_sha256": "d" * 64, "permit_consumed": True,
            "execution_permitted": False,
        }, execution_time)
        grant_envelope = {"grant": {
            "grant_id": grant_id, "task_id": task["task_id"],
            "runner_id": runner_id, "lease_generation": 1,
            "plan_digest": task["plan_digest"], "expires_at": iso(grant_expiry),
        }, "signature": {"fixture": True}}
        self.store._db.execute(
            "INSERT INTO execution_grants (grant_id,task_id,tenant_id,lease_generation,envelope_json,"
            "grant_sha256,expires_at,issued_at,consumed_at,consumed_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (grant_id, task["task_id"], "lab-tenant", 1, json.dumps(grant_envelope),
             "d" * 64, iso(grant_expiry), iso(execution_time - timedelta(seconds=30)),
             iso(execution_time), runner_id),
        )
        attestation = {
            "schema_version": "a2z-runner-attestation-v1", "receipt_id": str(uuid4()),
            "task_id": task["task_id"], "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": task["operation_id"], "environment": "lab",
            "plan_digest": task["plan_digest"], "lease_generation": 1, "runner_id": runner_id,
            "started_at": iso(receipt_start), "completed_at": iso(receipt_end),
            "outcome": "succeeded", "changed": True, "pre_state_sha256": "a" * 64,
            "post_state_sha256": "b" * 64, "network_calls": 0, "credentials_issued": False,
        }
        envelope = {"attestation": attestation, "signature": {"fixture": "signed"}}

        class HistoricalVerifier:
            def verify_historical(inner, received, *, expected_claims):
                self.assertEqual(received, envelope)
                self.assertEqual(expected_claims["runner_id"], runner_id)
                return received["attestation"], "e" * 64

        result = self.store.reconcile_late_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", runner_id=runner_id,
            signed_attestation=envelope, verifier=HistoricalVerifier(),
        )
        self.assertEqual(result["task_status"], "verification")
        self.assertFalse(result["execution_permitted"])
        self.assertEqual(self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"], "verification")
        self.assertEqual(self.store.list_postcondition_candidates(
            tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
            operation_ids=frozenset({task["operation_id"]}), environments=frozenset({"lab"}),
        )[0]["task_id"], task["task_id"])
        self.assertGreater(self.store.verify_events(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant",
        )["events"], 0)
        replay = self.store.reconcile_late_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", runner_id=runner_id,
            signed_attestation=envelope, verifier=HistoricalVerifier(),
        )
        self.assertTrue(replay["idempotent_replay"])

    def _prepare_postcondition_task(self):
        from uuid import uuid4

        plan = {
            "schema_version": "a2z-task-plan-v1",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vm-lab-1"], "environment": "lab",
            "preconditions": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Unlabeled"},
            "desired_state": {"description": "A2Z-Control-Plane-Demo"},
            "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
            "max_runtime_seconds": 30,
        }
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant",
            operation_id=plan["operation_id"], target_ids=("vm-lab-1",),
            environment="lab", plan=plan,
        )
        token = f"postcondition-token-{uuid4()}"
        lease_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        self.store._db.execute(
            "UPDATE tasks SET status='running',lease_owner='runner-lab-1',lease_until=?,lease_token=?,"
            "lease_stage='execution',lease_generation=1,execution_deadline=? WHERE task_id=?",
            (lease_until, token, lease_until, task["task_id"]),
        )
        now = datetime.now(timezone.utc).isoformat()
        runner_attestation = {
            "schema_version": "a2z-runner-attestation-v1", "receipt_id": str(uuid4()),
            "task_id": task["task_id"], "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": task["operation_id"], "environment": "lab",
            "plan_digest": task["plan_digest"], "lease_generation": 1,
            "runner_id": "runner-lab-1", "started_at": now, "completed_at": now,
            "outcome": "succeeded", "changed": True, "pre_state_sha256": "a" * 64,
            "post_state_sha256": "b" * 64, "network_calls": 0, "credentials_issued": False,
        }

        class RunnerVerifier:
            def verify(self, envelope, *, expected_claims):
                return envelope["attestation"], "c" * 64

        runner_evidence = self.store.record_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=token,
            signed_attestation={"attestation": runner_attestation, "signature": {"test": "signed"}},
            verifier=RunnerVerifier(),
        )
        observer_attestation = {
            "schema_version": "a2z-postcondition-attestation-v1",
            "verification_id": str(uuid4()), "receipt_id": runner_evidence["receipt_id"],
            "task_id": task["task_id"], "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": task["operation_id"], "environment": "lab",
            "plan_digest": task["plan_digest"], "lease_generation": 1,
            "verifier_id": "observer-lab-1", "observed_at": now,
            "observed_state": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Demo"},
        }

        class PostconditionVerifier:
            def verify(self, envelope, *, expected_claims):
                self.expected_claims = expected_claims
                payload = json.dumps({
                    "domain": "a2z.postcondition-attestation.v1",
                    "attestation": envelope["attestation"],
                }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                return envelope["attestation"], hashlib.sha256(payload).hexdigest()

        verifier = PostconditionVerifier()
        envelope = {"attestation": observer_attestation, "signature": {"test": "observer-signed"}}
        return task, envelope, verifier, token

    def test_independent_postcondition_attestation_completes_exact_matching_task(self):
        task, envelope, verifier, _ = self._prepare_postcondition_task()
        candidates = self.store.list_postcondition_candidates(
            tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            environments=frozenset({"lab"}),
        )
        self.assertEqual([candidate["task_id"] for candidate in candidates], [task["task_id"]])
        self.assertNotIn("plan", candidates[0])
        self.assertNotIn("runner_attestation", candidates[0])
        result = self.store.record_postcondition_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant",
            signed_attestation=envelope, verifier=verifier,
        )
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["postcondition_verified"])
        self.assertFalse(result["execution_permitted"])
        self.assertEqual(self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"], "completed")
        class ReplayVerifier:
            def verify(self, *args, **kwargs):
                raise AssertionError("an already accepted exact envelope should replay without re-verification")

        replay = self.store.record_postcondition_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant",
            signed_attestation=envelope, verifier=ReplayVerifier(),
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertTrue(self.store.verify_events(goal_id=self.goal.goal_id, tenant_id="lab-tenant")["events"] >= 5)

    def test_postcondition_candidate_listing_is_exactly_scoped_bounded_and_metadata_only(self):
        task, _, _, _ = self._prepare_postcondition_task()
        with self.assertRaisesRegex(PermissionError, "forbidden environment"):
            self.store.list_postcondition_candidates(
                tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
                operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
                environments=frozenset({"production"}),
            )
        with self.assertRaisesRegex(ValueError, "page size"):
            self.store.list_postcondition_candidates(
                tenant_id="lab-tenant", target_ids=frozenset({"vm-lab-1"}),
                operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
                environments=frozenset({"lab"}), limit=101,
            )
        outside = self.store.list_postcondition_candidates(
            tenant_id="lab-tenant", target_ids=frozenset({"other-vm"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            environments=frozenset({"lab"}),
        )
        self.assertEqual(outside, [])

    def test_independent_postcondition_mismatch_blocks_task_and_opens_breaker(self):
        task, envelope, verifier, _ = self._prepare_postcondition_task()
        envelope["attestation"]["observed_state"]["description"] = "unapproved-state"
        result = self.store.record_postcondition_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant",
            signed_attestation=envelope, verifier=verifier,
        )
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["verified"])
        self.assertEqual(self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"], "blocked")
        breaker = self.store.get_circuit_breaker(
            tenant_id="lab-tenant", target_id="vm-lab-1",
            operation_id="virtualbox.vm.set_demo_description",
        )
        self.assertEqual(breaker["state"], "open")

    def test_execution_lease_is_fenced_and_expiry_blocks_automatic_retry(self):
        from uuid import uuid4

        plan = make_plan("virtualbox.vm.start", ("vm-lab-1",), "lab", desired_state={"power_state": "running"})
        task = self.store.add_task(
            goal_id=self.goal.goal_id, tenant_id="lab-tenant", operation_id="virtualbox.vm.start",
            target_ids=("vm-lab-1",), environment="lab", plan=plan,
        )
        policy_lease = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab-tenant", worker_id="policy-test")
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=policy_lease["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )
        approval_id = str(uuid4())

        class Verifier:
            def verify(inner_self, signed_record, *, expected_scope):
                return {"approval_id": approval_id, "approver_id": "operator-approver", "request_id": self.goal.goal_id}

        verifier = Verifier()
        signed_record = {"approval": {"test": "signed"}, "signature": {"test": "sig"}}
        self.store.queue_task(task_id=task["task_id"], tenant_id="lab-tenant", signed_approval=signed_record, approval_verifier=verifier)
        lease = self.store.claim_execution_lease(
            task_id=task["task_id"], tenant_id="lab-tenant", worker_id="runner-lab-1",
            approval_verifier=verifier, lease_seconds=60,
        )
        self.assertEqual(lease["status"], "leased")
        self.assertEqual(lease["lease_generation"], 1)
        self.assertFalse(lease["execution_permitted"])
        self.assertNotIn("lease_token", self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant"))
        class GrantSigner:
            calls = 0

            def sign(inner_self, grant):
                inner_self.calls += 1
                return {"grant": grant, "signature": {"algorithm": "ed25519", "key_id": "test-issuer", "signature_base64": "AA=="}}

        class GrantVerifier:
            def verify(inner_self, envelope, *, expected_claims):
                inner_self.claims = expected_claims
                return envelope["grant"], "d" * 64

        class OpenControl:
            def assert_enabled(inner_self):
                return "e" * 64

        grant_signer, grant_verifier = GrantSigner(), GrantVerifier()
        execution_control = OpenControl()
        self.store._db.execute(
            "INSERT INTO circuit_breakers (tenant_id,target_id,operation_id,environment,state,goal_id,task_id,last_receipt_id,reason,opened_at) VALUES (?,?,?,?,'open',?,?,?,?,?)",
            ("lab-tenant", "vm-lab-1", "virtualbox.vm.start", "lab", self.goal.goal_id,
             task["task_id"], "receipt-open", "prior failure", "2026-01-01T00:00:00Z"),
        )
        with self.assertRaisesRegex(PermissionError, "circuit breaker is open"):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
                execution_control=execution_control,
            )
        self.store._db.execute(
            "DELETE FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
            ("lab-tenant", "vm-lab-1", "virtualbox.vm.start"),
        )
        with self.assertRaises(PermissionError):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token="stale",
                approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
                execution_control=execution_control,
            )
        issued = self.store.issue_execution_grant(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
            execution_control=execution_control,
        )
        grant_body = issued["grant"]["grant"]
        self.assertEqual(grant_body["lease_generation"], lease["lease_generation"])
        self.assertEqual(grant_body["approval_id"], approval_id)
        self.assertEqual(grant_body["lease_token_sha256"], hashlib.sha256(lease["lease_token"].encode()).hexdigest())
        self.assertFalse(issued["execution_permitted"])
        replay = self.store.issue_execution_grant(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
            execution_control=execution_control,
        )
        self.assertEqual(replay["grant"], issued["grant"])
        self.assertEqual(grant_signer.calls, 1)

        class ClosedControl:
            def assert_enabled(inner_self):
                raise PermissionError("global execution kill switch is engaged")

        with self.assertRaisesRegex(PermissionError, "kill switch is engaged"):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
                execution_control=ClosedControl(),
            )
        self.assertEqual(grant_signer.calls, 1)
        self.store._db.execute(
            "UPDATE execution_grants SET grant_sha256=? WHERE task_id=?",
            ("0" * 64, task["task_id"]),
        )
        with self.assertRaisesRegex(PermissionError, "stored execution grant integrity"):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
                execution_control=execution_control,
            )
        self.store._db.execute(
            "UPDATE execution_grants SET grant_sha256=? WHERE task_id=?",
            (issued["grant_sha256"], task["task_id"]),
        )
        with self.assertRaises(PermissionError):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token="stale",
                authenticated_runner_id="runner-lab-1", approval_verifier=verifier,
                grant_verifier=grant_verifier, execution_control=execution_control,
            )
        with self.assertRaisesRegex(PermissionError, "does not own the active lease"):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                authenticated_runner_id="other-runner", approval_verifier=verifier,
                grant_verifier=grant_verifier, execution_control=execution_control,
            )
        with self.assertRaisesRegex(PermissionError, "kill switch is engaged"):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                authenticated_runner_id="runner-lab-1", approval_verifier=verifier,
                grant_verifier=grant_verifier, execution_control=ClosedControl(),
            )
        self.store._db.execute(
            "INSERT INTO circuit_breakers (tenant_id,target_id,operation_id,environment,state,goal_id,task_id,last_receipt_id,reason,opened_at) VALUES (?,?,?,?,'open',?,?,?,?,?)",
            ("lab-tenant", "vm-lab-1", "virtualbox.vm.start", "lab", self.goal.goal_id,
             task["task_id"], "receipt-open-at-consume", "failure after grant issue", "2026-01-01T00:00:00Z"),
        )
        with self.assertRaisesRegex(PermissionError, "circuit breaker is open"):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                authenticated_runner_id="runner-lab-1", approval_verifier=verifier,
                grant_verifier=grant_verifier, execution_control=execution_control,
            )
        self.store._db.execute(
            "DELETE FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
            ("lab-tenant", "vm-lab-1", "virtualbox.vm.start"),
        )
        running = self.store.start_leased_task(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            authenticated_runner_id="runner-lab-1", approval_verifier=verifier,
            grant_verifier=grant_verifier, execution_control=execution_control,
        )
        self.assertEqual(running["status"], "running")
        self.assertTrue(running["permit_consumed"])
        self.assertFalse(running["execution_permitted"])
        with self.assertRaisesRegex(PermissionError, "current, unexpired fenced execution lease"):
            self.store.issue_execution_grant(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                approval_verifier=verifier, grant_signer=grant_signer, grant_verifier=grant_verifier,
                execution_control=execution_control,
            )
        consumed = self.store._db.execute(
            "SELECT consumed_at,consumed_by FROM execution_grants WHERE task_id=?",
            (task["task_id"],),
        ).fetchone()
        self.assertEqual(consumed["consumed_by"], "runner-lab-1")
        self.assertTrue(consumed["consumed_at"])
        with self.assertRaisesRegex(PermissionError, "current, unexpired fenced execution lease"):
            self.store.start_leased_task(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                authenticated_runner_id="runner-lab-1", approval_verifier=verifier,
                grant_verifier=grant_verifier, execution_control=execution_control,
            )
        verifying = self.store.begin_task_verification(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            runner_receipt_digest="b" * 64,
        )
        self.assertEqual(verifying["status"], "verification")
        from uuid import uuid4

        receipt = {
            "attestation": {
                "receipt_id": str(uuid4()), "task_id": task["task_id"],
                "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
                "operation_id": "virtualbox.vm.start", "environment": "lab",
                "plan_digest": task["plan_digest"], "lease_generation": lease["lease_generation"],
                "runner_id": "runner-lab-1", "outcome": "failed", "changed": True,
            },
            "signature": {"algorithm": "ed25519", "key_id": "runner-lab"},
        }

        class RunnerVerifier:
            digest = "c" * 64

            def verify(inner_self, envelope, *, expected_claims):
                inner_self.expected_claims = expected_claims
                return envelope["attestation"], inner_self.digest

        runner_verifier = RunnerVerifier()
        with self.assertRaisesRegex(PermissionError, "does not match the verification record"):
            self.store.record_runner_attestation(
                task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
                signed_attestation=receipt, verifier=runner_verifier,
            )
        runner_verifier.digest = "b" * 64
        evidence = self.store.record_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            signed_attestation=receipt, verifier=runner_verifier,
        )
        self.assertEqual(evidence["status"], "verified_evidence_only")
        self.assertEqual(runner_verifier.expected_claims["runner_id"], "runner-lab-1")
        self.assertFalse(evidence["postcondition_verified"])
        self.assertEqual(self.store.get_task(task_id=task["task_id"], tenant_id="lab-tenant")["status"], "verification")
        self.assertEqual(
            self.store.get_circuit_breaker(
                tenant_id="lab-tenant", target_id="vm-lab-1", operation_id="virtualbox.vm.start",
            )["state"],
            "open",
        )

        class ResetVerifier:
            def verify(inner_self, signed_record, *, expected_scope):
                inner_self.scope = expected_scope
                return {"approval_id": str(uuid4()), "approver_id": "operator-2", "request_id": self.goal.goal_id}

        reset_verifier = ResetVerifier()
        reset = self.store.reset_circuit_breaker(
            tenant_id="lab-tenant", target_id="vm-lab-1", operation_id="virtualbox.vm.start",
            evidence_digest="f" * 64, signed_approval={"approval": "signed"},
            approval_verifier=reset_verifier,
        )
        self.assertEqual(reset["state"], "closed")
        self.assertEqual(reset_verifier.scope["action"], "control_plane.circuit_breaker.reset")
        self.assertIn("evidence.sha256:" + "f" * 64, reset_verifier.scope["capabilities"])
        replay = self.store.record_runner_attestation(
            task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"],
            signed_attestation=receipt, verifier=runner_verifier,
        )
        self.assertTrue(replay["idempotent_replay"])
        self.store._db.execute("UPDATE tasks SET lease_until='2000-01-01T00:00:00Z' WHERE task_id=?", (task["task_id"],))
        blocked = self.store.recover_expired_execution_lease(task_id=task["task_id"], tenant_id="lab-tenant")
        self.assertEqual(blocked["status"], "blocked")
        with self.assertRaises(PermissionError):
            self.store.renew_execution_lease(task_id=task["task_id"], tenant_id="lab-tenant", lease_token=lease["lease_token"])
        self.assertTrue(self.store.verify_events(goal_id=self.goal.goal_id, tenant_id="lab-tenant")["events"] >= 8)


if __name__ == "__main__":
    unittest.main()
