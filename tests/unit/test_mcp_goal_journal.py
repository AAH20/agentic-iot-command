from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from control_plane_core.autonomy import AutonomyProfile, AutonomyRule
from control_plane_core.goals import DurableGoalStore
from control_plane_core.impact_assessments import VerifiedImpactAssessment, impact_assessment_digest
from scripts.mcp_goal_journal import dispatch, load_settings


class GoalJournalMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-goal-mcp-")
        self.store = DurableGoalStore(Path(self.temp.name) / "goals.sqlite3")
        self.guardrails = {
            "profile_id": "lab-default", "autonomy_enabled": False,
            "allowed_environments": ["lab"], "allowed_targets": ["vbox-host-1"],
            "critical_decisions": "operator_approval", "production_mutations": "deny",
            "generic_shell": "deny",
        }

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def call(self, name, arguments, request_id=1, approval_verifier=None,
             autonomy_profile=None, impact_verifier=None, autonomy_profile_verifier=None):
        return dispatch(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
             "params": {"name": name, "arguments": arguments}},
            store=self.store, tenant_id="lab", requested_by="operator-1",
            baseline_guardrails=self.guardrails, autonomy_profile=autonomy_profile,
            approval_verifier=approval_verifier, impact_verifier=impact_verifier,
            autonomy_profile_verifier=autonomy_profile_verifier,
        )

    def test_submit_uses_configured_guardrails_and_has_no_execution_capability(self):
        result = self.call("submit_infrastructure_goal", {
            "objective": "Report unhealthy lab VMs and propose next steps",
            "idempotency_key": "mcp-goal-1",
            "guardrails": {"autonomy_enabled": True},
        })
        self.assertTrue(result["result"]["isError"])
        accepted = self.call("submit_infrastructure_goal", {
            "objective": "Report unhealthy lab VMs and propose next steps",
            "idempotency_key": "mcp-goal-1",
        })
        self.assertNotIn("isError", accepted["result"])
        self.assertFalse(json.loads(accepted["result"]["content"][0]["text"])["execution_permitted"])

    def test_status_is_tenant_scoped(self):
        accepted = self.call("submit_infrastructure_goal", {
            "objective": "Inspect the lab only",
            "idempotency_key": "mcp-goal-2",
        })
        goal_id = json.loads(accepted["result"]["content"][0]["text"])["goal_id"]
        status = self.call("get_infrastructure_goal_status", {"goal_id": goal_id})
        payload = json.loads(status["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "submitted")
        self.assertFalse(payload["execution_permitted"])

    def test_task_proposal_is_typed_allowlisted_and_pending_policy(self):
        accepted = self.call("submit_infrastructure_goal", {
            "objective": "Inspect the lab only", "idempotency_key": "mcp-goal-task",
        })
        goal_id = json.loads(accepted["result"]["content"][0]["text"])["goal_id"]
        denied = self.call("propose_infrastructure_task", {
            "goal_id": goal_id, "operation_id": "virtualbox.vm.start",
            "target_ids": ["unregistered-vm"], "environment": "lab",
        })
        self.assertTrue(denied["result"]["isError"])
        task = self.call("propose_infrastructure_task", {
            "goal_id": goal_id, "operation_id": "virtualbox.vm.refresh_inventory",
            "target_ids": ["vbox-host-1"], "environment": "lab",
            "plan": {
                "schema_version": "a2z-task-plan-v1", "operation_id": "virtualbox.vm.refresh_inventory",
                "target_ids": ["vbox-host-1"], "environment": "lab",
                "preconditions": {"host_reachable": True},
                "desired_state": {"inventory_fresh": True},
                "rollback": {"strategy": "none", "reason": "read_only"}, "max_runtime_seconds": 300,
            },
        })
        payload = json.loads(task["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "pending_policy")
        self.assertFalse(payload["execution_permitted"])
        evaluated = self.call("evaluate_infrastructure_task", {"task_id": payload["task_id"]})
        result = json.loads(evaluated["result"]["content"][0]["text"])
        self.assertEqual(result["status"], "denied")
        self.assertIn("no_verified_signed_autonomy_profile", result["decision"]["reasons"])

    def test_impact_assessment_is_verified_against_stored_task_and_audited(self):
        goal = self.call("submit_infrastructure_goal", {
            "objective": "Review a disposable lab VM", "idempotency_key": "assessment-bound-goal",
        })
        goal_id = json.loads(goal["result"]["content"][0]["text"])["goal_id"]
        proposal = self.call("propose_infrastructure_task", {
            "goal_id": goal_id, "operation_id": "virtualbox.vm.start",
            "target_ids": ["vbox-host-1"], "environment": "lab",
            "plan": {
                "schema_version": "a2z-task-plan-v1", "operation_id": "virtualbox.vm.start",
                "target_ids": ["vbox-host-1"], "environment": "lab",
                "preconditions": {"power_state": "powered_off"},
                "desired_state": {"power_state": "running"},
                "rollback": {"strategy": "operator_review"}, "max_runtime_seconds": 120,
            },
        })
        task = json.loads(proposal["result"]["content"][0]["text"])
        assessment_envelope = {
            "assessment": {"schema_version": "a2z-impact-assessment-v1", "plan_digest": task["plan_digest"]},
            "signature": {"algorithm": "ed25519", "key_id": "test", "signature_base64": "c2ln"},
        }
        assessment_digest = impact_assessment_digest(assessment_envelope)

        class Verifier:
            def verify(inner_self, envelope, *, expected):
                inner_self.expected = expected
                return VerifiedImpactAssessment(
                    tenant_id=expected["tenant_id"], task_id=expected["task_id"],
                    operation_id=expected["operation_id"], target_ids=expected["target_ids"],
                    environment=expected["environment"], plan_digest=expected["plan_digest"],
                    affected_resource_count=1, estimated_cost_microusd=100,
                    source_id="trusted-test-estimator", assessment_digest=assessment_digest,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                )

        now = datetime.now(timezone.utc)
        policy = AutonomyProfile(
            profile_id="lab-default", tenant_id="lab", expires_at=now + timedelta(minutes=20),
            rules=(AutonomyRule(
                action_id="virtualbox.vm.start", target_ids=("vbox-host-1",), environments=("lab",),
                max_targets_per_run=1, max_batch_size=1, enabled=True,
                max_affected_resources=1, max_estimated_cost_microusd=1000,
            ),),
            verified_signature=True, max_concurrency=1, max_total_targets=1, enabled=True,
            policy_digest="b" * 64, max_affected_resources=1, max_estimated_cost_microusd=1000,
        )
        verifier = Verifier()
        result = self.call("evaluate_infrastructure_task", {
            "task_id": task["task_id"], "impact_assessment": assessment_envelope,
        }, autonomy_profile=policy, impact_verifier=verifier)
        payload = json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "approval_required")
        self.assertFalse(payload["execution_permitted"])
        self.assertEqual(payload["decision"]["impact_assessment_digest"], assessment_digest)
        self.assertEqual(payload["decision"]["impact_assessment"], assessment_envelope)
        self.assertEqual(verifier.expected["plan_digest"], task["plan_digest"])
        self.assertEqual(verifier.expected["target_ids"], ("vbox-host-1",))

    def test_non_code_owned_demo_description_plan_is_denied_end_to_end(self):
        goal = self.call("submit_infrastructure_goal", {
            "objective": "Apply the fixed metadata label to one lab VM",
            "idempotency_key": "demo-description-plan-goal",
        })
        goal_id = json.loads(goal["result"]["content"][0]["text"])["goal_id"]
        plan = {
            "schema_version": "a2z-task-plan-v1",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vbox-host-1"], "environment": "lab",
            "preconditions": {
                "power_state": "powered_off",
                "description": "A2Z-Control-Plane-Unlabeled",
            },
            "desired_state": {"description": "attacker-chosen-value"},
            "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
            "max_runtime_seconds": 30,
        }
        proposed = self.call("propose_infrastructure_task", {
            "goal_id": goal_id, "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vbox-host-1"], "environment": "lab", "plan": plan,
        })
        task = json.loads(proposed["result"]["content"][0]["text"])
        now = datetime.now(timezone.utc)
        profile = AutonomyProfile(
            profile_id="lab-demo", tenant_id="lab", expires_at=now + timedelta(minutes=10),
            rules=(AutonomyRule(
                action_id="virtualbox.vm.set_demo_description",
                target_ids=("vbox-host-1",), environments=("lab",),
                max_targets_per_run=1, max_batch_size=1, enabled=True,
                max_affected_resources=1, max_estimated_cost_microusd=0,
            ),), verified_signature=True, max_concurrency=1, max_total_targets=1,
            enabled=True, policy_digest="c" * 64, max_affected_resources=1,
            max_estimated_cost_microusd=0,
        )
        evaluated = self.call("evaluate_infrastructure_task", {"task_id": task["task_id"]},
                              autonomy_profile=profile)
        result = json.loads(evaluated["result"]["content"][0]["text"])
        self.assertEqual(result["status"], "denied")
        self.assertIn("demo_description_desired_state_not_code_owned", result["decision"]["reasons"])
        self.assertFalse(result["execution_permitted"])

    def test_signed_task_approval_tool_only_queues_and_binds_signature_scope(self):
        from uuid import uuid4

        goal_result = self.call("submit_infrastructure_goal", {
            "objective": "Review a lab VM operation", "idempotency_key": "signed-approval-goal",
        })
        goal_id = json.loads(goal_result["result"]["content"][0]["text"])["goal_id"]
        task_result = self.call("propose_infrastructure_task", {
            "goal_id": goal_id, "operation_id": "virtualbox.vm.start",
            "target_ids": ["vbox-host-1"], "environment": "lab",
            "plan": {
                "schema_version": "a2z-task-plan-v1", "operation_id": "virtualbox.vm.start",
                "target_ids": ["vbox-host-1"], "environment": "lab",
                "preconditions": {"power_state": "poweroff"},
                "desired_state": {"power_state": "running"},
                "rollback": {"strategy": "operator_review"}, "max_runtime_seconds": 300,
            },
        })
        task = json.loads(task_result["result"]["content"][0]["text"])
        lease = self.store.claim_policy_task(task_id=task["task_id"], tenant_id="lab", worker_id="policy-test")
        self.store.record_decision(
            task_id=task["task_id"], tenant_id="lab", lease_token=lease["lease_token"],
            disposition="approval_required", reasons=("high_impact",), policy_digest="",
        )

        class Verifier:
            def verify(inner_self, signed_record, *, expected_scope):
                inner_self.scope = expected_scope
                return {"approval_id": str(uuid4()), "approver_id": "operator-approver", "request_id": goal_id}

        verifier = Verifier()
        result = self.call("queue_approved_infrastructure_task", {
            "task_id": task["task_id"], "signed_approval": {"approval": {}, "signature": {}},
        }, approval_verifier=verifier)
        payload = json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "queued")
        self.assertFalse(payload["execution_permitted"])
        self.assertEqual(verifier.scope["plan_id"], task["task_id"])
        self.assertIn("plan.sha256:" + task["plan_digest"], verifier.scope["capabilities"])

    def test_policy_queue_tool_requires_verified_configured_autonomy(self):
        result = self.call("queue_policy_authorized_infrastructure_task", {"task_id": "task-1"})
        self.assertTrue(result["result"]["isError"])
        self.assertIn("not configured", result["result"]["content"][0]["text"])

    def test_policy_queue_tool_routes_only_task_id_and_trusted_verifiers(self):
        expected = {"status": "queued", "execution_permitted": False}
        observed = {}

        def queue_autonomous_task(**kwargs):
            observed.update(kwargs)
            return expected

        self.store.queue_autonomous_task = queue_autonomous_task
        profile_verifier, impact_verifier = object(), object()
        result = self.call(
            "queue_policy_authorized_infrastructure_task", {"task_id": "task-1"},
            autonomy_profile=object(), autonomy_profile_verifier=profile_verifier,
            impact_verifier=impact_verifier,
        )
        payload = json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(payload, expected)
        self.assertEqual(observed, {
            "task_id": "task-1", "tenant_id": "lab",
            "autonomy_profile_verifier": profile_verifier,
            "impact_verifier": impact_verifier,
        })

    def test_local_config_cannot_enable_autonomy_without_signed_policy(self):
        config_path = Path(self.temp.name) / "mcp.json"
        config_path.write_text(json.dumps({
            "tenant_id": "lab", "requested_by": "operator-1",
            "database_path": str(Path(self.temp.name) / "configured.sqlite3"),
            "autonomy_profile_path": None, "trust_directory": None, "impact_trust_directory": None,
            "baseline_guardrails": {**self.guardrails, "autonomy_enabled": True},
        }), encoding="utf-8")
        config_path.chmod(0o600)
        with self.assertRaises(PermissionError):
            load_settings(config_path, allow_user_owned_config=True)

    def test_root_managed_group_readable_config_is_accepted_but_broad_access_is_not(self):
        config_path = Path(self.temp.name) / "gateway.json"
        config = {
            "tenant_id": "lab", "requested_by": "operator-1",
            "database_path": str(Path(self.temp.name) / "gateway.sqlite3"),
            "autonomy_profile_path": None, "trust_directory": None, "impact_trust_directory": None,
            "baseline_guardrails": self.guardrails,
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o640)
        store, _, _, _, _, _, _ = load_settings(config_path, allow_user_owned_config=True)
        store.close()
        config_path.chmod(0o644)
        with self.assertRaises(PermissionError):
            load_settings(config_path, allow_user_owned_config=True)


if __name__ == "__main__":
    unittest.main()
