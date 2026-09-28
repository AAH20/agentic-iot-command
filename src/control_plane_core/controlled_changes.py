from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from .evidence import EvidenceLedger
from .lifecycle import ChangeLifecycle, ExecutionReceipt, VerificationResult
from .models import AuthorizationRequest
from .registry import LocalControlPlaneStore
from .service import ControlPlane
from .verification import PostChangeVerifier


@dataclass
class ChangeWorkflow:
    lifecycle: ChangeLifecycle
    approver_ids: set[str] = field(default_factory=set)

    @property
    def workflow_id(self) -> UUID:
        return self.lifecycle.plan_id


class ControlledChangeService:
    """Coordinates the signed-approval, simulation, verification, and evidence stages."""

    def __init__(self, store: LocalControlPlaneStore, evidence: EvidenceLedger, *, control_plane: ControlPlane | None = None, verifier: PostChangeVerifier | None = None, repository: Any | None = None) -> None:
        self.store = store
        self.evidence = evidence
        self.control_plane = control_plane or store.control_plane
        self.verifier = verifier or PostChangeVerifier()
        self.repository = repository
        self._workflows: dict[UUID, ChangeWorkflow] = {}

    def start(self, request: AuthorizationRequest) -> dict[str, Any]:
        if request.mode != "mutate":
            raise ValueError("controlled change workflow requires mutate mode")
        self.store.create_request(request)
        lifecycle = ChangeLifecycle.start(request, self.control_plane)
        workflow = ChangeWorkflow(lifecycle=lifecycle)
        self._workflows[workflow.workflow_id] = workflow
        self._record(workflow, "change.workflow.started")
        return self.describe(workflow_id=workflow.workflow_id, tenant_id=request.tenant_id)

    def approval_scope_for_request(self, request_id: UUID) -> dict[str, Any]:
        for workflow in self._workflows.values():
            request = workflow.lifecycle.request
            if request.request_id == request_id:
                return {
                    "tenant_id": request.tenant_id,
                    "target": request.target,
                    "action": request.action,
                    "environment": request.environment,
                    "capabilities": sorted(request.capabilities),
                    "plan_id": str(workflow.workflow_id),
                }
        raise KeyError("change workflow not found for authorization request")

    def approve(self, *, workflow_id: UUID, tenant_id: str, approval_id: str) -> dict[str, Any]:
        workflow = self._get(workflow_id, tenant_id)
        record = self.store.approvals.get(approval_id)
        if record is None:
            raise KeyError("verified approval not found")
        lifecycle = workflow.lifecycle
        if record.request_id != str(lifecycle.request.request_id) or record.tenant_id != tenant_id or record.plan_id != str(lifecycle.plan_id):
            raise PermissionError("approval does not match workflow request and tenant")
        if not record.signature_verified:
            raise PermissionError("approval signature has not been verified")
        if record.approver_id in workflow.approver_ids:
            raise ValueError("a distinct approver is required for each approval")
        try:
            expires_at = datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("approval expiry is invalid") from exc
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise PermissionError("approval has expired")
        is_second_approver = bool(workflow.approver_ids)
        lifecycle.approve(approval_id, second_approver=is_second_approver)
        workflow.approver_ids.add(record.approver_id)
        self._record(workflow, "change.workflow.approval_recorded", {"approval_id": approval_id, "approver_id": record.approver_id})
        return self.describe(workflow_id=workflow_id, tenant_id=tenant_id)

    def dispatch(self, *, workflow_id: UUID, tenant_id: str) -> dict[str, Any]:
        workflow = self._get(workflow_id, tenant_id)
        receipt = workflow.lifecycle.dispatch_simulated()
        self._record(
            workflow,
            "change.workflow.simulated_dispatch",
            {
                "receipt": {
                    "receipt_id": str(receipt.receipt_id),
                    "plan_id": str(receipt.plan_id),
                    "runner_id": receipt.runner_id,
                    "simulation": receipt.simulation,
                    "credentials_issued": receipt.credentials_issued,
                    "network_calls": receipt.network_calls,
                }
            },
        )
        result = self.describe(workflow_id=workflow_id, tenant_id=tenant_id)
        result["receipt"] = {
            "receipt_id": str(receipt.receipt_id),
            "plan_id": str(receipt.plan_id),
            "runner_id": receipt.runner_id,
            "simulation": receipt.simulation,
            "credentials_issued": receipt.credentials_issued,
            "network_calls": receipt.network_calls,
            "tenant_id": receipt.tenant_id,
            "resource_id": receipt.resource_id,
        }
        return result

    def verify(self, *, workflow_id: UUID, tenant_id: str, expected_state: dict[str, Any], observed_state: dict[str, Any]) -> dict[str, Any]:
        workflow = self._get(workflow_id, tenant_id)
        receipt = workflow.lifecycle.receipt
        if receipt is None:
            raise RuntimeError("workflow has no simulated execution receipt")
        report = self.verifier.verify(
            receipt=receipt,
            tenant_id=tenant_id,
            resource_id=workflow.lifecycle.request.target,
            expected_state=expected_state,
            observed_state=observed_state,
        )
        workflow.lifecycle.verify(success=report.verified)
        self._record(workflow, "change.workflow.verification_completed", report.as_dict())
        return report.as_dict() | {"workflow_id": str(workflow_id), "state": workflow.lifecycle.state}

    def rollback(self, *, workflow_id: UUID, tenant_id: str) -> dict[str, Any]:
        workflow = self._get(workflow_id, tenant_id)
        workflow.lifecycle.rollback()
        self._record(workflow, "change.workflow.rollback_recorded")
        return self.describe(workflow_id=workflow_id, tenant_id=tenant_id)

    def describe(self, *, workflow_id: UUID, tenant_id: str) -> dict[str, Any]:
        workflow = self._get(workflow_id, tenant_id)
        lifecycle = workflow.lifecycle
        return {
            "workflow_id": str(workflow_id),
            "request_id": str(lifecycle.request.request_id),
            "plan_id": str(lifecycle.plan_id),
            "tenant_id": tenant_id,
            "target": lifecycle.request.target,
            "environment": lifecycle.request.environment,
            "state": lifecycle.state,
            "approval_ids": list(lifecycle.approval_ids),
            "approver_count": len(workflow.approver_ids),
            "execution_permitted": False,
        }

    def _get(self, workflow_id: UUID, tenant_id: str) -> ChangeWorkflow:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            raise KeyError("change workflow not found")
        if workflow.lifecycle.request.tenant_id != tenant_id:
            raise PermissionError("change workflow crosses tenant boundary")
        return workflow

    def _record(self, workflow: ChangeWorkflow, event_type: str, details: dict[str, Any] | None = None) -> None:
        lifecycle = workflow.lifecycle
        payload = {
            "tenant_id": lifecycle.request.tenant_id,
            "workflow_id": str(workflow.workflow_id),
            "request_id": str(lifecycle.request.request_id),
            "plan_id": str(lifecycle.plan_id),
            "state": lifecycle.state,
            "details": details or {},
        }
        if self.repository is not None:
            self.repository.save_change_workflow(
                tenant_id=lifecycle.request.tenant_id, plan=self._snapshot(workflow),
                event_type=event_type, event_payload=payload,
                create=workflow.workflow_id not in getattr(self, "_persisted_workflows", set()),
            )
            self._persisted_workflows = getattr(self, "_persisted_workflows", set()) | {workflow.workflow_id}
            return
        self.evidence.record(tenant_id=lifecycle.request.tenant_id, event_type=event_type,
                             collector="local-control-plane-api/0.1", payload=payload)

    @staticmethod
    def _snapshot(workflow: ChangeWorkflow) -> dict[str, Any]:
        lifecycle = workflow.lifecycle
        receipt = asdict(lifecycle.receipt) if lifecycle.receipt else None
        verification = asdict(lifecycle.verification) if lifecycle.verification else None
        if receipt:
            receipt = {key: str(value) if isinstance(value, UUID) else value for key, value in receipt.items()}
        if verification:
            verification = {key: str(value) if isinstance(value, UUID) else list(value) if isinstance(value, tuple) else value for key, value in verification.items()}
        return {
            "plan_id": str(lifecycle.plan_id),
            "request_id": str(lifecycle.request.request_id),
            "workflow": {
                "state": lifecycle.state,
                "approval_ids": list(lifecycle.approval_ids),
                "approver_ids": sorted(workflow.approver_ids),
                "events": lifecycle.events,
                "receipt": receipt,
                "verification": verification,
            },
        }

    def restore_persisted(self, tenant_id: str, snapshots: list[dict[str, Any]]) -> None:
        """Rehydrate workflow state only from tenant-scoped persisted plans."""
        for snapshot in snapshots:
            request_id = str(snapshot.get("request_id", ""))
            request = self.store.requests.get(request_id)
            state_data = snapshot.get("workflow")
            if request is None or request.tenant_id != tenant_id or not isinstance(state_data, dict):
                continue
            lifecycle = ChangeLifecycle(
                request=request, control_plane=self.control_plane,
                plan_id=UUID(str(snapshot["plan_id"])), state=state_data["state"],
                approval_ids=list(state_data.get("approval_ids", [])),
                events=list(state_data.get("events", [])),
            )
            receipt = state_data.get("receipt")
            if isinstance(receipt, dict):
                lifecycle.receipt = ExecutionReceipt(
                    receipt_id=UUID(receipt["receipt_id"]), plan_id=UUID(receipt["plan_id"]),
                    runner_id=receipt["runner_id"], simulation=receipt["simulation"],
                    credentials_issued=receipt["credentials_issued"], network_calls=receipt["network_calls"],
                    status=receipt["status"], tenant_id=receipt["tenant_id"], resource_id=receipt["resource_id"],
                )
            verification = state_data.get("verification")
            if isinstance(verification, dict):
                lifecycle.verification = VerificationResult(
                    verification_id=UUID(verification["verification_id"]),
                    receipt_id=UUID(verification["receipt_id"]), verified=verification["verified"],
                    checks=tuple(verification["checks"]), rollback_available=verification["rollback_available"],
                )
            workflow = ChangeWorkflow(lifecycle=lifecycle, approver_ids=set(state_data.get("approver_ids", [])))
            self._workflows[workflow.workflow_id] = workflow
            self._persisted_workflows = getattr(self, "_persisted_workflows", set()) | {workflow.workflow_id}
