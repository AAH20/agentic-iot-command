from __future__ import annotations

import json
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from control_plane_core.runner_preflight import VerifiedExecutionPreflight
from control_plane_core.virtualbox_adapter import VirtualBoxDemoAdapter


class Preflight:
    def __init__(self, checked):
        self.checked = checked
        self.calls = 0

    def verify(self, envelope, *, task_id, authenticated_runner_id):
        self.calls += 1
        if envelope != {"grant": "signed"} or task_id != self.checked.task_id or authenticated_runner_id != "runner-1":
            raise PermissionError("bad preflight scope")
        return self.checked


class Control:
    def __init__(self, digest="e" * 64):
        self.digest = digest
        self.calls = 0

    def assert_enabled(self):
        self.calls += 1
        if self.digest is None:
            raise PermissionError("worker kill switch is engaged")
        return self.digest


class PermitConsumer:
    def __init__(self):
        self.calls = []
        self.allow = True

    def consume_execution_permit(self, *, task_id, runner_id, grant_digest):
        self.calls.append((task_id, runner_id, grant_digest))
        if not self.allow:
            return {"permit_consumed": False}
        return {"task_id": task_id, "runner_id": runner_id,
                "grant_digest": grant_digest, "permit_consumed": True}


class VirtualBoxAdapterTests(unittest.TestCase):
    def setUp(self):
        self.target = str(uuid4())
        self.task_id = str(uuid4())
        self.plan = {
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "target_ids": [self.target],
            "preconditions": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Unlabeled"},
            "desired_state": {"description": "A2Z-Control-Plane-Demo"},
            "rollback": {"description": "A2Z-Control-Plane-Unlabeled"},
            "max_runtime_seconds": 30,
        }
        self.checked = VerifiedExecutionPreflight(
            task_id=self.task_id, tenant_id="lab", target_id=self.target,
            operation_id=self.plan["operation_id"], environment="lab",
            plan_digest="a" * 64, grant_digest="b" * 64,
            grant_expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
            max_runtime_seconds=30, plan=self.plan,
        )
        self.state = {"VMState": "poweroff", "description": "A2Z-Control-Plane-Unlabeled"}
        self.calls = []

        def command_runner(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if argv[1] == "showvminfo":
                stdout = "\n".join(f'{key}={json.dumps(value)}' for key, value in self.state.items())
                return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
            if argv[1] == "modifyvm":
                self.state["description"] = argv[4]
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=9, stdout="", stderr="")

        # A fixed, trusted system executable passes the production path checks;
        # the injected command runner ensures no process is launched by the test.
        self.executable = Path("/usr/bin/openssl")
        self.preflight = Preflight(self.checked)
        self.control = Control()
        self.consumer = PermitConsumer()
        self.adapter = VirtualBoxDemoAdapter(
            preflight=self.preflight, execution_control=self.control,
            permit_consumer=self.consumer,
            vboxmanage=str(self.executable), command_runner=command_runner,
        )

    def tearDown(self):
        pass

    def test_runs_only_exact_typed_metadata_action_and_verifies_postcondition(self):
        result = self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                      authenticated_runner_id="runner-1")
        self.assertEqual(result.before["description"], "A2Z-Control-Plane-Unlabeled")
        self.assertEqual(result.after["description"], "A2Z-Control-Plane-Demo")
        self.assertEqual(result.grant_digest, "b" * 64)
        self.assertFalse(result.rollback_attempted)
        mutation = [call for call in self.calls if call[0][1] == "modifyvm"]
        self.assertEqual(len(mutation), 1)
        self.assertEqual(mutation[0][0], [str(self.executable), "modifyvm", self.target,
                                           "--description", "A2Z-Control-Plane-Demo"])
        self.assertIs(mutation[0][1]["shell"], False)
        self.assertEqual(self.preflight.calls, 2)
        self.assertEqual(self.control.calls, 3)
        self.assertEqual(self.consumer.calls, [(self.task_id, "runner-1", "b" * 64)])

    def test_refuses_wrong_state_plan_or_disabled_worker_control_before_mutation(self):
        self.state["description"] = "operator-value"
        with self.assertRaisesRegex(PermissionError, "exact approved preconditions"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")
        self.assertFalse(any(call[0][1] == "modifyvm" for call in self.calls))

        self.state["description"] = "A2Z-Control-Plane-Unlabeled"
        self.plan["desired_state"] = {"description": "arbitrary value"}
        with self.assertRaisesRegex(PermissionError, "exact single-VM"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")
        self.assertFalse(any(call[0][1] == "modifyvm" for call in self.calls))

    def test_worker_kill_switch_and_command_failures_fail_closed(self):
        self.control.digest = None
        with self.assertRaisesRegex(PermissionError, "kill switch"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")
        self.assertFalse(self.calls)

        self.control.digest = "e" * 64
        self.consumer.allow = False
        with self.assertRaisesRegex(PermissionError, "one-shot permit consumption"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")
        self.assertFalse(any(call[0][1] == "modifyvm" for call in self.calls))

    def test_lease_preflight_is_rechecked_before_mutation_and_drift_blocks_action(self):
        initial = {"VMState": "poweroff", "description": "A2Z-Control-Plane-Unlabeled"}
        observations = 0

        def drifting_runner(argv, **kwargs):
            nonlocal observations
            if argv[1] == "showvminfo":
                observations += 1
                current = initial if observations == 1 else {**initial, "description": "operator-change"}
                return SimpleNamespace(returncode=0, stdout="\n".join(
                    f'{key}={json.dumps(value)}' for key, value in current.items()), stderr="")
            self.fail("mutation must not run after drift")

        self.adapter.command_runner = drifting_runner
        with self.assertRaisesRegex(PermissionError, "changed after precondition"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")

    def test_uncertain_mutation_result_triggers_only_exact_verified_rollback(self):
        calls = []

        def ambiguous_runner(argv, **kwargs):
            calls.append(argv)
            if argv[1] == "showvminfo":
                stdout = "\n".join(f'{key}={json.dumps(value)}' for key, value in self.state.items())
                return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
            self.state["description"] = argv[4]
            # Model VBoxManage returning failure even though the side effect landed.
            status = 0 if argv[4] == "A2Z-Control-Plane-Unlabeled" else 7
            return SimpleNamespace(returncode=status, stdout="", stderr="uncertain")

        self.adapter.command_runner = ambiguous_runner
        with self.assertRaisesRegex(RuntimeError, "rollback verified"):
            self.adapter.execute({"grant": "signed"}, task_id=self.task_id,
                                 authenticated_runner_id="runner-1")
        self.assertEqual(self.state["description"], "A2Z-Control-Plane-Unlabeled")
        mutations = [argv for argv in calls if argv[1] == "modifyvm"]
        self.assertEqual(mutations, [
            [str(self.executable), "modifyvm", self.target,
             "--description", "A2Z-Control-Plane-Demo"],
            [str(self.executable), "modifyvm", self.target,
             "--description", "A2Z-Control-Plane-Unlabeled"],
        ])


if __name__ == "__main__":
    unittest.main()
