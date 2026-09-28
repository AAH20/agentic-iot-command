from datetime import datetime, timedelta, timezone
import unittest

from control_plane_core.autonomy import (
    ActionRisk,
    AutonomyDisposition,
    AutonomyPolicyEngine,
    AutonomyProfile,
    AutonomyRequest,
    AutonomyRule,
    MaintenanceWindow,
    OperationContract,
)
from control_plane_core.autonomy_catalog import TRUSTED_OPERATION_CONTRACTS
from control_plane_core.impact_assessments import VerifiedImpactAssessment


NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)
CONTRACT = OperationContract(
    action_id="virtualbox.vm.refresh_inventory",
    risk=ActionRisk.ROUTINE,
    idempotent=True,
    reversible=True,
    rollback_supported=True,
    verification_supported=True,
)


def profile(**overrides):
    values = {
        "profile_id": "lab-autonomy-v1",
        "tenant_id": "lab",
        "expires_at": NOW + timedelta(hours=1),
        "rules": (AutonomyRule(
            action_id=CONTRACT.action_id,
            target_ids=("vbox-host-01",),
            environments=("lab",),
            max_targets_per_run=1,
            max_batch_size=1,
            enabled=True,
            max_affected_resources=1,
            max_estimated_cost_microusd=25_000_000,
        ),),
        "verified_signature": True,
        "max_concurrency": 1,
        "max_total_targets": 1,
        "max_affected_resources": 1,
        "max_estimated_cost_microusd": 25_000_000,
        "enabled": True,
        "policy_digest": "b" * 64,
        "maintenance_windows": (MaintenanceWindow(
            window_id="routine-lab", action_id=CONTRACT.action_id,
            target_ids=("vbox-host-01",), environments=("lab",),
            starts_at=NOW - timedelta(minutes=1), ends_at=NOW + timedelta(hours=1),
        ),),
    }
    values.update(overrides)
    return AutonomyProfile(**values)


def request(**overrides):
    values = {
        "tenant_id": "lab",
        "action_id": CONTRACT.action_id,
        "target_ids": ("vbox-host-01",),
        "environment": "lab",
        "batch_size": 1,
        "active_concurrency": 0,
        "plan_digest": "a" * 64,
        "task_id": "00000000-0000-4000-8000-000000000001",
        "max_runtime_seconds": 60,
        "impact_assessment": assessment(),
    }
    values.update(overrides)
    return AutonomyRequest(**values)


def assessment(**overrides):
    values = {
        "tenant_id": "lab",
        "task_id": "00000000-0000-4000-8000-000000000001",
        "operation_id": CONTRACT.action_id,
        "target_ids": ("vbox-host-01",),
        "environment": "lab",
        "plan_digest": "a" * 64,
        "affected_resource_count": 1,
        "estimated_cost_microusd": 0,
        "source_id": "signed-lab-estimator",
        "assessment_digest": "c" * 64,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    return VerifiedImpactAssessment(**values)


class AutonomyPolicyTests(unittest.TestCase):
    def test_signed_bounded_routine_action_is_eligible_but_never_dispatched(self):
        result = AutonomyPolicyEngine().evaluate(profile(), request(), CONTRACT, now=NOW)

        self.assertIs(result.disposition, AutonomyDisposition.AUTO_ELIGIBLE)
        self.assertEqual(result.reason_codes, ("signed_bounded_routine_rule_matches",))
        self.assertFalse(result.execution_permitted)

    def test_code_owned_demo_metadata_action_is_preeligible_only_under_exact_bounds(self):
        action_id = "virtualbox.vm.set_demo_description"
        target = "lab-vm-01"
        contract = TRUSTED_OPERATION_CONTRACTS[action_id]
        policy = profile(rules=(AutonomyRule(
            action_id=action_id, target_ids=(target,), environments=("lab",),
            max_targets_per_run=1, max_batch_size=1, enabled=True,
            max_affected_resources=1, max_estimated_cost_microusd=0,
        ),), max_estimated_cost_microusd=0, maintenance_windows=(MaintenanceWindow(
            window_id="demo-window", action_id=action_id, target_ids=(target,),
            environments=("lab",), starts_at=NOW - timedelta(minutes=1),
            ends_at=NOW + timedelta(hours=1),
        ),))
        signed_estimate = assessment(
            operation_id=action_id, target_ids=(target,), estimated_cost_microusd=0,
        )
        task = request(
            action_id=action_id, target_ids=(target,), impact_assessment=signed_estimate,
        )
        result = AutonomyPolicyEngine().evaluate(policy, task, contract, now=NOW)
        self.assertIs(result.disposition, AutonomyDisposition.AUTO_ELIGIBLE)
        self.assertFalse(result.execution_permitted)
        self.assertEqual(result.impact_assessment_digest, "c" * 64)

    def test_critical_risk_never_becomes_autonomous(self):
        for risk in (
            ActionRisk.HIGH_IMPACT,
            ActionRisk.DESTRUCTIVE,
            ActionRisk.PROVISION,
            ActionRisk.DECOMMISSION,
            ActionRisk.SECURITY_BOUNDARY,
        ):
            with self.subTest(risk=risk):
                contract = OperationContract(
                    action_id=CONTRACT.action_id,
                    risk=risk,
                    idempotent=True,
                    reversible=True,
                    rollback_supported=True,
                    verification_supported=True,
                )

                result = AutonomyPolicyEngine().evaluate(profile(), request(), contract, now=NOW)

                self.assertIs(result.disposition, AutonomyDisposition.APPROVAL_REQUIRED)
                self.assertIn("high_impact_action_requires_human_approval", result.reason_codes)

    def test_virtualbox_power_operations_are_code_owned_high_impact(self):
        for action_id in ("virtualbox.vm.start", "virtualbox.vm.acpi_shutdown"):
            contract = TRUSTED_OPERATION_CONTRACTS[action_id]
            with self.subTest(action_id=action_id):
                current_profile = profile(rules=(AutonomyRule(
                    action_id=action_id, target_ids=("vbox-host-01",), environments=("lab",),
                    max_targets_per_run=1, max_batch_size=1, enabled=True,
                    max_affected_resources=1, max_estimated_cost_microusd=25_000_000,
                ),))
                result = AutonomyPolicyEngine().evaluate(
                    current_profile,
                    request(action_id=action_id),
                    contract,
                    now=NOW,
                )
                self.assertIs(result.disposition, AutonomyDisposition.APPROVAL_REQUIRED)
                self.assertIn("high_impact_action_requires_human_approval", result.reason_codes)

    def test_missing_governance_condition_requires_operator_approval(self):
        cases = (
            ("unsigned", "standing_policy_signature_not_verified"),
            ("wrong_target", "target_not_in_exact_allowlist"),
            ("production", "environment_not_eligible_for_autonomy"),
            ("window_closed", "approved_maintenance_window_not_open"),
            ("batch_too_large", "batch_limit_exceeded"),
            ("concurrency_full", "concurrency_limit_reached"),
            ("not_reversible", "operation_lacks_verified_rollback"),
            ("privileged", "privileged_identity_excluded_from_auto_execution"),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                current_profile = (
                    profile(verified_signature=False) if case == "unsigned"
                    else profile(maintenance_windows=()) if case == "window_closed"
                    else profile()
                )
                current_request = request(
                    target_ids=("other-host",) if case == "wrong_target" else ("vbox-host-01",),
                    environment="production" if case == "production" else "lab",
                    batch_size=2 if case == "batch_too_large" else 1,
                    active_concurrency=1 if case == "concurrency_full" else 0,
                )
                current_contract = OperationContract(
                    action_id=CONTRACT.action_id,
                    risk=ActionRisk.ROUTINE,
                    idempotent=True,
                    reversible=case != "not_reversible",
                    rollback_supported=case != "not_reversible",
                    verification_supported=True,
                    uses_privileged_identity=case == "privileged",
                )

                result = AutonomyPolicyEngine().evaluate(current_profile, current_request, current_contract, now=NOW)

                self.assertIs(result.disposition, AutonomyDisposition.APPROVAL_REQUIRED)
                self.assertIn(expected, result.reason_codes)
                self.assertFalse(result.execution_permitted)

    def test_window_is_exactly_scoped_and_must_cover_full_task_runtime(self):
        engine = AutonomyPolicyEngine()
        wrong_scope = profile(maintenance_windows=(MaintenanceWindow(
            window_id="wrong-target", action_id=CONTRACT.action_id,
            target_ids=("other-host",), environments=("lab",),
            starts_at=NOW - timedelta(minutes=1), ends_at=NOW + timedelta(hours=1),
        ),))
        outside = engine.evaluate(wrong_scope, request(), CONTRACT, now=NOW)
        self.assertIn("approved_maintenance_window_not_open", outside.reason_codes)

        short_window = profile(maintenance_windows=(MaintenanceWindow(
            window_id="short", action_id=CONTRACT.action_id,
            target_ids=("vbox-host-01",), environments=("lab",),
            starts_at=NOW - timedelta(minutes=1), ends_at=NOW + timedelta(seconds=30),
        ),))
        too_long = engine.evaluate(short_window, request(max_runtime_seconds=60), CONTRACT, now=NOW)
        self.assertIn("action_would_outlive_maintenance_window", too_long.reason_codes)
        self.assertIs(too_long.disposition, AutonomyDisposition.APPROVAL_REQUIRED)

    def test_expired_revoked_unknown_and_generic_shell_actions_fail_closed(self):
        engine = AutonomyPolicyEngine()
        expired = profile(expires_at=NOW)
        revoked = profile(revoked=True)
        shell = request(action_id="shell.exec")

        self.assertIs(engine.evaluate(expired, request(), CONTRACT, now=NOW).disposition, AutonomyDisposition.DENY)
        self.assertIs(engine.evaluate(revoked, request(), CONTRACT, now=NOW).disposition, AutonomyDisposition.DENY)
        self.assertIs(engine.evaluate(profile(), shell, None, now=NOW).disposition, AutonomyDisposition.DENY)

    def test_missing_or_over_budget_impact_estimates_require_approval(self):
        engine = AutonomyPolicyEngine()
        cases = (
            (request(impact_assessment=None), "trusted_impact_estimate_missing_or_invalid"),
            (request(impact_assessment=assessment(affected_resource_count=2)), "affected_resource_limit_exceeded"),
            (request(impact_assessment=assessment(estimated_cost_microusd=25_000_001)), "estimated_cost_limit_exceeded"),
            (request(impact_assessment=assessment(plan_digest="d" * 64)), "trusted_impact_estimate_missing_or_invalid"),
        )
        for current_request, reason in cases:
            with self.subTest(reason=reason):
                result = engine.evaluate(profile(), current_request, CONTRACT, now=NOW)
                self.assertIs(result.disposition, AutonomyDisposition.APPROVAL_REQUIRED)
                self.assertIn(reason, result.reason_codes)
                self.assertFalse(result.execution_permitted)


if __name__ == "__main__":
    unittest.main()
