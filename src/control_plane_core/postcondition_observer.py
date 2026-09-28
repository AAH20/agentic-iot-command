from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

from .autonomy_catalog import validate_operation_plan
from .postcondition_attestations import Ed25519PostconditionAttestationSigner


class IndependentVirtualBoxPostconditionObserver:
    """Read-only observer for journal-verified demo tasks; never receives runner commands."""

    OPERATION_ID = "virtualbox.vm.set_demo_description"

    def __init__(self, *, journal: Any, verifier_id: str,
                 signer: Ed25519PostconditionAttestationSigner,
                 vboxmanage: str = "/usr/bin/VBoxManage",
                 command_runner: Callable[..., Any] | None = None,
                 timeout_seconds: int = 10) -> None:
        if journal is None or signer is None:
            raise PermissionError("authoritative journal and separate postcondition signer are required")
        if not isinstance(verifier_id, str) or not verifier_id.strip() or len(verifier_id) > 256:
            raise ValueError("verifier identity must be a specific bounded identifier")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            raise ValueError("observer timeout must be between 1 and 30 seconds")
        self.journal = journal
        self.verifier_id = verifier_id
        self.signer = signer
        self.vboxmanage = Path(vboxmanage)
        self.command_runner = command_runner or subprocess.run
        self.timeout_seconds = timeout_seconds

    def attest_task(self, *, task_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch a verification candidate from the journal, observe state, and sign it."""
        candidate = self.journal.get_postcondition_candidate(task_id=task_id, tenant_id=tenant_id)
        if not isinstance(candidate, dict) or candidate.get("task_id") != task_id or candidate.get("tenant_id") != tenant_id:
            raise PermissionError("journal returned a task outside the requested observer scope")
        target_id = candidate.get("target_id")
        try:
            UUID(target_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise PermissionError("observer target must be one exact VirtualBox UUID") from exc
        if candidate.get("operation_id") != self.OPERATION_ID or candidate.get("environment") != "lab":
            raise PermissionError("observer supports only the fixed VirtualBox lab metadata operation")
        plan = candidate.get("plan")
        if (not isinstance(plan, dict) or plan.get("operation_id") != self.OPERATION_ID
                or plan.get("target_ids") != [target_id] or plan.get("environment") != "lab"
                or validate_operation_plan(self.OPERATION_ID, plan)):
            raise PermissionError("journal plan does not match the independent observer contract")
        if _digest(plan) != candidate.get("plan_digest"):
            raise PermissionError("journal plan digest does not match the observer candidate")
        generation = candidate.get("lease_generation")
        runner_envelope = candidate.get("runner_attestation")
        if (isinstance(generation, bool) or not isinstance(generation, int) or generation < 1
                or not isinstance(runner_envelope, dict) or not isinstance(runner_envelope.get("attestation"), dict)):
            raise PermissionError("journal candidate lacks a valid runner receipt and lease generation")
        runner = runner_envelope["attestation"]
        receipt_id = runner.get("receipt_id")
        try:
            UUID(receipt_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise PermissionError("journal runner receipt ID is invalid") from exc
        expected_runner_claims = {
            "task_id": task_id, "tenant_id": tenant_id, "target_id": target_id,
            "operation_id": self.OPERATION_ID, "environment": "lab",
            "plan_digest": candidate["plan_digest"], "lease_generation": generation,
        }
        if any(runner.get(key) != value for key, value in expected_runner_claims.items()):
            raise PermissionError("stored runner receipt does not match the journal task")
        if runner.get("outcome") not in {"succeeded", "already_satisfied"}:
            raise PermissionError("failed or unknown runner outcome is not eligible for success verification")

        self._validate_executable()
        observed_state = self._show_vm(target_id)
        attestation = {
            "schema_version": "a2z-postcondition-attestation-v1",
            "verification_id": str(uuid4()), "receipt_id": receipt_id,
            **expected_runner_claims, "verifier_id": self.verifier_id,
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "observed_state": observed_state,
        }
        return self.signer.sign(attestation)

    def attest_and_submit(self, *, task_id: str, tenant_id: str, outbox: Any) -> dict[str, Any]:
        """Persist a signed observation before delivery and retry only that exact envelope."""
        if outbox is None:
            raise PermissionError("durable postcondition outbox is required before submission")
        pending = outbox.pending_for_task(task_id=task_id)
        if pending is None:
            envelope = self.attest_task(task_id=task_id, tenant_id=tenant_id)
            outbox.put(envelope=envelope)
            pending = outbox.pending_for_task(task_id=task_id)
        if pending is None or pending.get("tenant_id") != tenant_id:
            raise PermissionError("pending postcondition evidence does not match the requested tenant")
        envelope = pending.get("envelope")
        body = envelope.get("attestation") if isinstance(envelope, dict) else None
        if (not isinstance(body, dict) or body.get("task_id") != task_id
                or body.get("tenant_id") != tenant_id or body.get("verifier_id") != self.verifier_id):
            raise PermissionError("pending postcondition evidence does not match the observer identity")
        result = self.journal.record_postcondition_attestation(
            task_id=task_id, tenant_id=tenant_id, signed_attestation=envelope,
        )
        if result.get("task_id") != task_id:
            raise PermissionError("journal returned a postcondition result outside the requested task")
        outbox.mark_delivered(verification_id=pending["verification_id"])
        return result

    def run_once(self, *, outbox: Any, limit: int = 20) -> list[dict[str, Any]]:
        """Replay pending evidence first, then observe and submit a bounded ready page."""
        if outbox is None:
            raise PermissionError("durable postcondition outbox is required before submission")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("postcondition observer page size must be between 1 and 100")
        results: list[dict[str, Any]] = []
        # A committed response may have been lost, so retry its exact envelope before
        # polling only tasks still in verification.
        for pending in outbox.pending(limit=limit):
            body = pending["envelope"]["attestation"]
            if (body.get("verifier_id") != self.verifier_id
                    or pending.get("tenant_id") != self.journal.tenant_id):
                raise PermissionError("pending outbox record belongs to another verifier identity or tenant")
            result = self.journal.record_postcondition_attestation(
                task_id=pending["task_id"], tenant_id=pending["tenant_id"],
                signed_attestation=pending["envelope"],
            )
            if result.get("task_id") != pending["task_id"]:
                raise PermissionError("journal returned a result outside the pending outbox task")
            outbox.mark_delivered(verification_id=pending["verification_id"])
            results.append(result)
        candidates = self.journal.list_postcondition_candidates(limit=limit)
        if not isinstance(candidates, list) or len(candidates) > limit:
            raise PermissionError("postcondition candidate source returned an invalid bounded page")
        for candidate in candidates:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("task_id"), str):
                raise PermissionError("postcondition candidate source returned malformed metadata")
            results.append(self.attest_and_submit(
                task_id=candidate["task_id"], tenant_id=self.journal.tenant_id, outbox=outbox,
            ))
        return results

    def _validate_executable(self) -> None:
        path = self.vboxmanage
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise PermissionError("observer requires the fixed absolute VBoxManage executable")
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("VBoxManage must be root-owned and not group/other writable")
        for parent in path.parents:
            if (parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != 0
                    or stat.S_IMODE(parent.stat().st_mode) & 0o022):
                raise PermissionError("VBoxManage parent directories must be real, root-owned, and not group/other writable")

    def _show_vm(self, target_id: str) -> dict[str, str]:
        try:
            result = self.command_runner(
                [str(self.vboxmanage), "showvminfo", target_id, "--machinereadable"],
                check=False, capture_output=True, text=True, timeout=self.timeout_seconds,
                close_fds=True, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("read-only VirtualBox observation failed closed") from exc
        if result.returncode != 0 or not isinstance(result.stdout, str):
            raise RuntimeError("read-only VirtualBox observation returned an error")
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, raw = line.partition("=")
            if not separator or key not in {"VMState", "description"}:
                continue
            if key in values:
                raise RuntimeError("VirtualBox observer received duplicate state fields")
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raise RuntimeError("VirtualBox observer received malformed state") from None
            if not isinstance(value, str):
                raise RuntimeError("VirtualBox observer received a non-string state value")
            values[key] = value
        if set(values) != {"VMState", "description"}:
            raise RuntimeError("VirtualBox observer did not receive the exact required state fields")
        return {
            "power_state": {"poweroff": "powered_off"}.get(values["VMState"], values["VMState"]),
            "description": values["description"],
        }


def _digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
