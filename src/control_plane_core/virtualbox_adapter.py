from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from .autonomy_catalog import DEMO_DESCRIPTION, DEMO_DESCRIPTION_INITIAL
from .runner_preflight import RunnerPreflight, VerifiedExecutionPreflight


class OneShotPermitConsumer:
    """Authenticated journal client that atomically consumes the grant once.

    A live implementation must use the runner's workload identity, derive its
    identity from the authenticated channel, and bind consumption to current
    lease generation, task, grant digest, and the control-plane kill switch.
    """

    def consume_execution_permit(self, *, task_id: str, runner_id: str,
                                 grant_digest: str) -> dict[str, Any]:
        raise NotImplementedError


@dataclass(frozen=True)
class VirtualBoxActionResult:
    task_id: str
    target_id: str
    operation_id: str
    before: dict[str, str]
    after: dict[str, str]
    grant_digest: str
    execution_control_digest: str
    rollback_attempted: bool
    rollback_verified: bool | None


class VirtualBoxDemoAdapter:
    """Single-operation VirtualBox adapter; never accepts shell text or arbitrary argv.

    The adapter intentionally supports only the code-owned, reversible demo-label
    operation. The supplied preflight must fetch current lease state over an
    authenticated channel and verify the signed grant before every invocation.
    """

    OPERATION_ID = "virtualbox.vm.set_demo_description"

    def __init__(self, *, preflight: RunnerPreflight, execution_control: Any,
                 permit_consumer: OneShotPermitConsumer,
                 vboxmanage: str = "/usr/bin/VBoxManage",
                 command_runner: Callable[..., Any] | None = None) -> None:
        if preflight is None or execution_control is None or permit_consumer is None:
            raise PermissionError("live lease preflight, one-shot permit consumer, and worker-side execution control are required")
        self.preflight = preflight
        self.execution_control = execution_control
        self.permit_consumer = permit_consumer
        self.vboxmanage = Path(vboxmanage)
        self.command_runner = command_runner or subprocess.run

    def execute(self, envelope: dict[str, Any], *, task_id: str,
                authenticated_runner_id: str) -> VirtualBoxActionResult:
        checked = self.preflight.verify(
            envelope, task_id=task_id, authenticated_runner_id=authenticated_runner_id,
        )
        self._validate_action(checked)
        control_digest = self.execution_control.assert_enabled()
        if not isinstance(control_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", control_digest):
            raise PermissionError("worker execution-control verifier returned an invalid digest")
        self._validate_executable()

        deadline = min(
            time.monotonic() + checked.max_runtime_seconds,
            time.monotonic() + max(0.0, (checked.grant_expires_at.timestamp() - time.time())),
        )
        before = self._show_vm(checked.target_id, deadline)
        if before != {"power_state": "powered_off", "description": DEMO_DESCRIPTION_INITIAL}:
            raise PermissionError("live VM state no longer matches the exact approved preconditions")

        # Revalidate both the lease/grant and the independent worker kill switch
        # immediately before the only mutation verb.
        checked = self.preflight.verify(
            envelope, task_id=task_id, authenticated_runner_id=authenticated_runner_id,
        )
        self._validate_action(checked)
        control_digest = self.execution_control.assert_enabled()
        if not isinstance(control_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", control_digest):
            raise PermissionError("worker execution-control verifier returned an invalid digest")
        if self._show_vm(checked.target_id, deadline) != before:
            raise PermissionError("live VM state changed after precondition observation")
        consumed = self.permit_consumer.consume_execution_permit(
            task_id=checked.task_id, runner_id=authenticated_runner_id,
            grant_digest=checked.grant_digest,
        )
        if consumed != {
            "task_id": checked.task_id, "runner_id": authenticated_runner_id,
            "grant_digest": checked.grant_digest, "permit_consumed": True,
        }:
            raise PermissionError("control plane did not confirm one-shot permit consumption")
        # Last local breaker check after one-shot permit consumption and before
        # crossing the sole mutation boundary.
        control_digest = self.execution_control.assert_enabled()
        if not isinstance(control_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", control_digest):
            raise PermissionError("worker execution-control verifier returned an invalid digest")
        try:
            self._run([str(self.vboxmanage), "modifyvm", checked.target_id,
                       "--description", DEMO_DESCRIPTION], deadline)
            after = self._show_vm(checked.target_id, deadline)
            if after != {"power_state": "powered_off", "description": DEMO_DESCRIPTION}:
                raise RuntimeError("VirtualBox postcondition differs from the exact desired state")
        except Exception as cause:
            rollback_verified: bool | None = False
            try:
                self._validate_executable()
                current = self._show_vm(checked.target_id, deadline)
                if current == {"power_state": "powered_off", "description": DEMO_DESCRIPTION}:
                    self._run([str(self.vboxmanage), "modifyvm", checked.target_id,
                               "--description", DEMO_DESCRIPTION_INITIAL], deadline)
                    rollback_verified = self._show_vm(checked.target_id, deadline) == {
                        "power_state": "powered_off", "description": DEMO_DESCRIPTION_INITIAL,
                    }
            except Exception:
                rollback_verified = False
            raise RuntimeError(
                "VirtualBox action postcondition failed; rollback "
                + ("verified" if rollback_verified else "not verified")
            ) from cause

        return VirtualBoxActionResult(
            task_id=checked.task_id, target_id=checked.target_id,
            operation_id=checked.operation_id, before=before, after=after,
            grant_digest=checked.grant_digest, execution_control_digest=control_digest,
            rollback_attempted=False, rollback_verified=None,
        )

    def _validate_action(self, checked: VerifiedExecutionPreflight) -> None:
        if (checked.operation_id != self.OPERATION_ID or checked.environment != "lab"
                or checked.plan.get("desired_state") != {"description": DEMO_DESCRIPTION}
                or checked.plan.get("preconditions") != {
                    "power_state": "powered_off", "description": DEMO_DESCRIPTION_INITIAL,
                }
                or checked.plan.get("rollback") != {"description": DEMO_DESCRIPTION_INITIAL}
                or not _is_uuid(checked.target_id)):
            raise PermissionError("worker supports only the exact single-VM lab demo-description plan")

    def _validate_executable(self) -> None:
        path = self.vboxmanage
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise PermissionError("VBoxManage must be a fixed absolute executable, not a symlink")
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("VBoxManage must be root-owned and not group/other writable")
        for parent in path.parents:
            if (parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != 0
                    or stat.S_IMODE(parent.stat().st_mode) & 0o022):
                raise PermissionError("VBoxManage parent directories must be real, root-owned, and not group/other writable")

    def _show_vm(self, target_id: str, deadline: float) -> dict[str, str]:
        output = self._run([str(self.vboxmanage), "showvminfo", target_id, "--machinereadable"], deadline)
        values: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, raw = line.partition("=")
            if not separator or key not in {"VMState", "description"}:
                continue
            if key in values:
                raise RuntimeError("VBoxManage returned duplicate machine-readable state fields")
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raise RuntimeError("VBoxManage returned malformed machine-readable state") from None
            if not isinstance(value, str):
                raise RuntimeError("VBoxManage returned a non-string state value")
            values[key] = value
        if set(values) != {"VMState", "description"}:
            raise RuntimeError("VBoxManage omitted required VM state fields")
        state = {"poweroff": "powered_off"}.get(values["VMState"], values["VMState"])
        return {"power_state": state, "description": values["description"]}

    def _run(self, argv: list[str], deadline: float) -> str:
        timeout = min(10.0, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("VirtualBox action exceeded its signed runtime bound")
        try:
            result = self.command_runner(
                argv, check=False, capture_output=True, text=True, timeout=timeout,
                close_fds=True, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("fixed VirtualBox operation failed closed") from exc
        if result.returncode != 0:
            raise RuntimeError("fixed VirtualBox operation returned a non-zero status")
        return result.stdout


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except (ValueError, TypeError, AttributeError):
        return False
