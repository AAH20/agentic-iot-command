from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal
from uuid import UUID, uuid4

from .models import AuthorizationRequest
from .service import ControlPlane

LifecycleState = Literal["planned", "approval_pending", "approved", "dispatched", "verified", "failed", "rolled_back", "denied"]


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: UUID
    plan_id: UUID
    runner_id: str
    simulation: bool = True
    credentials_issued: bool = False
    network_calls: int = 0
    status: str = "dispatched"
    tenant_id: str = ""
    resource_id: str = ""


@dataclass(frozen=True)
class VerificationResult:
    verification_id: UUID
    receipt_id: UUID
    verified: bool
    checks: tuple[str, ...]
    rollback_available: bool = True


@dataclass
class ChangeLifecycle:
    request: AuthorizationRequest
    control_plane: ControlPlane
    plan_id: UUID = field(default_factory=uuid4)
    state: LifecycleState = "planned"
    approval_ids: list[str] = field(default_factory=list)
    events: list[dict[str, object]] = field(default_factory=list)
    receipt: ExecutionReceipt | None = None
    verification: VerificationResult | None = None

    @classmethod
    def start(cls, request: AuthorizationRequest, control_plane: ControlPlane) -> "ChangeLifecycle":
        lifecycle = cls(request=request, control_plane=control_plane)
        planning_request = replace(request, mode="plan", approvals=(), second_approver=False)
        decision = control_plane.authorize(planning_request)
        if decision.decision == "deny":
            lifecycle.state = "denied"
            lifecycle._event("denied", list(decision.reason_codes))
        else:
            lifecycle.state = "approval_pending"
            lifecycle._event("planned", list(decision.reason_codes))
        return lifecycle

    def approve(self, approval_id: str, *, second_approver: bool = False) -> None:
        if self.state != "approval_pending":
            raise RuntimeError(f"approval is not accepted in state {self.state}")
        if not approval_id.strip() or approval_id in self.approval_ids:
            raise ValueError("approval id must be non-empty and unique")
        self.approval_ids.append(approval_id)
        request = replace(
            self.request,
            mode="mutate",
            approvals=tuple(self.approval_ids),
            second_approver=second_approver,
        )
        decision = self.control_plane.authorize(request)
        if decision.decision == "allow":
            self.state = "approved"
            self._event("approved", list(decision.reason_codes))
        else:
            self._event("approval_pending", list(decision.reason_codes))

    def dispatch_simulated(self) -> ExecutionReceipt:
        if self.state != "approved":
            raise RuntimeError(f"dispatch requires approved state, got {self.state}")
        if self.request.environment not in {"lab", "development"}:
            raise PermissionError("simulation runner refuses production or regulated targets")
        self.receipt = ExecutionReceipt(
            receipt_id=uuid4(),
            plan_id=self.plan_id,
            runner_id=f"sim-runner-{uuid4().hex[:12]}",
            tenant_id=self.request.tenant_id,
            resource_id=self.request.target,
        )
        self.state = "dispatched"
        self._event("dispatched", ["simulation_only", "credentials_denied", "network_denied"])
        return self.receipt

    def verify(self, *, success: bool) -> VerificationResult:
        if self.state != "dispatched" or self.receipt is None:
            raise RuntimeError(f"verification requires dispatched state, got {self.state}")
        self.verification = VerificationResult(
            verification_id=uuid4(),
            receipt_id=self.receipt.receipt_id,
            verified=success,
            checks=("receipt_present", "simulation_constraints", "policy_state"),
        )
        self.state = "verified" if success else "failed"
        self._event(self.state, ["verification_passed" if success else "verification_failed"])
        return self.verification

    def rollback(self) -> None:
        if self.state != "failed":
            raise RuntimeError(f"rollback requires failed state, got {self.state}")
        self.state = "rolled_back"
        self._event("rolled_back", ["simulation_rollback_recorded"])

    def _event(self, state: str, reason_codes: list[str]) -> None:
        self.events.append({"state": state, "reason_codes": reason_codes})
