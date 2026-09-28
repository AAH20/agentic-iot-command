from __future__ import annotations

import unittest

from control_plane_core.autonomy import ActionRisk
from control_plane_core.autonomy_catalog import (
    DEMO_DESCRIPTION,
    DEMO_DESCRIPTION_INITIAL,
    TRUSTED_OPERATION_CONTRACTS,
    validate_operation_plan,
)


class AutonomyCatalogTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "schema_version": "a2z-task-plan-v1",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["lab-vm-01"],
            "environment": "lab",
            "preconditions": {"power_state": "powered_off", "description": DEMO_DESCRIPTION_INITIAL},
            "desired_state": {"description": DEMO_DESCRIPTION},
            "rollback": {"description": DEMO_DESCRIPTION_INITIAL},
            "max_runtime_seconds": 60,
        }

    def test_fixed_lab_metadata_action_is_routine_and_exact_plan_is_accepted(self):
        contract = TRUSTED_OPERATION_CONTRACTS["virtualbox.vm.set_demo_description"]
        self.assertIs(contract.risk, ActionRisk.ROUTINE)
        self.assertTrue(contract.idempotent and contract.reversible and contract.rollback_supported)
        self.assertEqual(validate_operation_plan(contract.action_id, self.plan), ())

    def test_plan_cannot_expand_description_mutation_scope(self):
        cases = (
            ("desired_state", {"description": "agent supplied arbitrary text"}),
            ("rollback", {"description": "unobserved prior value"}),
            ("preconditions", {"power_state": "saved", "description": DEMO_DESCRIPTION_INITIAL}),
        )
        for field, value in cases:
            with self.subTest(field=field):
                mutated = {**self.plan, field: value}
                self.assertTrue(validate_operation_plan("virtualbox.vm.set_demo_description", mutated))

    def test_plan_requires_single_lab_target_and_bounded_runtime(self):
        multi = {**self.plan, "target_ids": ["lab-vm-01", "lab-vm-02"]}
        production = {**self.plan, "environment": "production"}
        long_runtime = {**self.plan, "max_runtime_seconds": 121}
        for plan in (multi, production, long_runtime):
            with self.subTest(plan=plan):
                self.assertTrue(validate_operation_plan("virtualbox.vm.set_demo_description", plan))


if __name__ == "__main__":
    unittest.main()
