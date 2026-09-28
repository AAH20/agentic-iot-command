from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import uuid4

from .receipt_outbox import RunnerReceiptOutbox


class WorkerTransport(Protocol):
    runner_id: str

    def list_ready_tasks(self) -> list[dict[str, Any]]: ...
    def claim(self, *, task_id: str) -> dict[str, Any]: ...
    def issue_grant(self, *, task_id: str, lease_token: str) -> dict[str, Any]: ...
    def submit_attestation(self, *, task_id: str, signed_attestation: dict[str, Any], lease_token: str) -> dict[str, Any]: ...
    def reconcile_attestation(self, *, task_id: str, signed_attestation: dict[str, Any]) -> dict[str, Any]: ...


class RunnerReceiptSigner(Protocol):
    def sign(self, attestation: dict[str, Any]) -> dict[str, Any]: ...


class GovernedVirtualBoxWorker:
    """One-task coordinator for the single fixed VirtualBox demo-label adapter.

    This class does not discover arbitrary commands or enable the adapter. The
    adapter remains responsible for signed preflight, the worker kill switch,
    exact pre/postconditions, and one-shot permit consumption.
    """

    OPERATION_ID = "virtualbox.vm.set_demo_description"

    def __init__(self, *, transport: WorkerTransport, adapter: Any,
                 receipt_signer: RunnerReceiptSigner, outbox: RunnerReceiptOutbox) -> None:
        if transport is None or adapter is None or receipt_signer is None or outbox is None:
            raise PermissionError("worker transport, fixed adapter, receipt signer, and durable outbox are required")
        self.transport = transport
        self.adapter = adapter
        self.receipt_signer = receipt_signer
        self.outbox = outbox

    def process_next(self) -> dict[str, Any]:
        """Process at most one exact supported task; leave verification to a separate service."""
        pending_result = self._flush_outbox()
        if pending_result is not None:
            return pending_result
        ready = self.transport.list_ready_tasks()
        if not isinstance(ready, list) or len(ready) > 100:
            raise PermissionError("runner ready queue response is invalid or unbounded")
        for item in ready:
            if not isinstance(item, dict) or item.get("operation_id") != self.OPERATION_ID:
                continue
            task_id = item.get("task_id")
            if not isinstance(task_id, str) or item.get("environment") != "lab":
                continue
            try:
                lease = self.transport.claim(task_id=task_id)
            except (PermissionError, KeyError):
                # Another worker may have won the race, or revalidation may have
                # withdrawn authorization. Never infer permission from discovery.
                continue
            return self._process_claimed(item, lease)
        return {"status": "no_supported_ready_task", "execution_permitted": False}

    def _process_claimed(self, ready: dict[str, Any], lease: dict[str, Any]) -> dict[str, Any]:
        task_id = ready["task_id"]
        runner_id = self.transport.runner_id
        if (not isinstance(lease, dict) or lease.get("task_id") != task_id
                or lease.get("runner_id") != runner_id or lease.get("status") != "leased"
                or lease.get("environment") not in (None, "lab")
                or lease.get("plan_digest") != ready.get("plan_digest")
                or not isinstance(lease.get("lease_token"), str) or not lease["lease_token"]
                or isinstance(lease.get("lease_generation"), bool)
                or not isinstance(lease.get("lease_generation"), int)
                or lease["lease_generation"] < 1):
            raise PermissionError("claimed lease does not match discovered task and runner identity")
        grant_response = self.transport.issue_grant(task_id=task_id, lease_token=lease["lease_token"])
        if (not isinstance(grant_response, dict) or not isinstance(grant_response.get("grant"), dict)
                or not isinstance(grant_response.get("grant_sha256"), str)
                or grant_response.get("execution_permitted") is not False):
            raise PermissionError("grant issuer returned an invalid or unexpectedly permissive response")

        started = _now()
        result = self.adapter.execute(
            grant_response["grant"], task_id=task_id, authenticated_runner_id=runner_id,
        )
        if (result.task_id != task_id or result.operation_id != self.OPERATION_ID
                or result.target_id not in ready.get("target_ids", ())
                or result.before == result.after
                or result.rollback_attempted):
            raise PermissionError("fixed adapter returned an unexpected task or state result")
        completed = _now()
        attestation = {
            "schema_version": "a2z-runner-attestation-v1",
            "receipt_id": str(uuid4()), "task_id": task_id,
            "tenant_id": lease["tenant_id"], "target_id": result.target_id,
            "operation_id": result.operation_id, "environment": "lab",
            "plan_digest": lease["plan_digest"],
            "lease_generation": lease["lease_generation"], "runner_id": runner_id,
            "started_at": started, "completed_at": completed,
            "outcome": "succeeded", "changed": True,
            "pre_state_sha256": _digest(result.before),
            "post_state_sha256": _digest(result.after),
            # This operation performs no target-side network calls and receives
            # no credentials. Control-plane mTLS traffic is not target activity.
            "network_calls": 0, "credentials_issued": False,
        }
        envelope = self.receipt_signer.sign(attestation)
        self.outbox.put(
            task_id=task_id, lease_generation=lease["lease_generation"],
            lease_token=lease["lease_token"], envelope=envelope,
        )
        try:
            evidence = self.transport.submit_attestation(
                task_id=task_id, signed_attestation=envelope, lease_token=lease["lease_token"],
            )
        except PermissionError:
            return {"status": "pending_receipt_reconciliation_required", "task_id": task_id,
                    "receipt_id": attestation["receipt_id"], "execution_permitted": False}
        except ConnectionError:
            return {"status": "pending_receipt_delivery_deferred", "task_id": task_id,
                    "receipt_id": attestation["receipt_id"], "execution_permitted": False}
        _assert_receipt_ack(evidence, envelope)
        self.outbox.mark_delivered(receipt_id=attestation["receipt_id"])
        return {
            "status": "awaiting_independent_verification",
            "task_id": task_id, "receipt_id": attestation["receipt_id"],
            "attestation_sha256": evidence.get("attestation_sha256"),
            "execution_permitted": False, "postcondition_verified": False,
        }

    def _flush_outbox(self) -> dict[str, Any] | None:
        delivered = 0
        while delivered < 100:
            entries = self.outbox.pending(limit=min(100, 100 - delivered))
            if not entries:
                return None
            for entry in entries:
                try:
                    evidence = self.transport.submit_attestation(
                        task_id=entry["task_id"], signed_attestation=entry["envelope"],
                        lease_token=entry["lease_token"],
                    )
                except PermissionError:
                    reconcile = getattr(self.transport, "reconcile_attestation", None)
                    if not callable(reconcile):
                        return {"status": "pending_receipt_reconciliation_required",
                                "task_id": entry["task_id"], "receipt_id": entry["receipt_id"],
                                "execution_permitted": False}
                    try:
                        evidence = reconcile(
                            task_id=entry["task_id"], signed_attestation=entry["envelope"],
                        )
                    except PermissionError:
                        return {"status": "pending_receipt_reconciliation_required",
                                "task_id": entry["task_id"], "receipt_id": entry["receipt_id"],
                                "execution_permitted": False}
                    except ConnectionError:
                        return {"status": "pending_receipt_delivery_deferred",
                                "task_id": entry["task_id"], "receipt_id": entry["receipt_id"],
                                "execution_permitted": False}
                except ConnectionError:
                    return {"status": "pending_receipt_delivery_deferred",
                            "task_id": entry["task_id"], "receipt_id": entry["receipt_id"],
                            "execution_permitted": False}
                _assert_receipt_ack(evidence, entry["envelope"])
                self.outbox.mark_delivered(receipt_id=entry["receipt_id"])
                delivered += 1
        if self.outbox.pending(limit=1):
            return {"status": "outbox_backlog_requires_replay", "execution_permitted": False}
        return None


def _digest(state: dict[str, Any]) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _assert_receipt_ack(evidence: Any, envelope: dict[str, Any]) -> None:
    if (not isinstance(evidence, dict) or evidence.get("status") != "verified_evidence_only"
            or evidence.get("receipt_id") != envelope["attestation"].get("receipt_id")
            or evidence.get("execution_permitted") is not False
            or evidence.get("postcondition_verified") is not False):
        raise PermissionError("journal receipt acknowledgment does not match evidence-only contract")
