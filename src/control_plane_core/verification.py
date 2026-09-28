from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from .drift import DriftDetector
from .lifecycle import ExecutionReceipt


@dataclass(frozen=True)
class VerificationReport:
    verification_id: UUID
    receipt_id: UUID
    tenant_id: str
    resource_id: str
    verified: bool
    checks: tuple[str, ...]
    rollback_required: bool
    execution_permitted: bool = False
    credentials_issued: bool = False
    network_calls: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "verification_id": str(self.verification_id),
            "receipt_id": str(self.receipt_id),
            "tenant_id": self.tenant_id,
            "resource_id": self.resource_id,
            "verified": self.verified,
            "checks": list(self.checks),
            "rollback_required": self.rollback_required,
            "execution_permitted": self.execution_permitted,
            "credentials_issued": self.credentials_issued,
            "network_calls": self.network_calls,
        }


class PostChangeVerifier:
    """Verifies a simulation receipt and state without re-running a change."""

    def __init__(self, drift_detector: DriftDetector | None = None) -> None:
        self.drift_detector = drift_detector or DriftDetector()

    def verify(
        self,
        *,
        receipt: ExecutionReceipt,
        tenant_id: str,
        resource_id: str,
        expected_state: dict[str, Any],
        observed_state: dict[str, Any],
    ) -> VerificationReport:
        if not tenant_id.strip() or not resource_id.strip():
            raise ValueError("tenant and resource identifiers are required")
        if receipt.tenant_id and receipt.tenant_id != tenant_id:
            raise PermissionError("verification receipt crosses tenant boundary")
        if receipt.resource_id and receipt.resource_id != resource_id:
            raise PermissionError("verification receipt targets a different resource")
        self._assert_state_scope(expected_state, tenant_id, resource_id, "expected")
        self._assert_state_scope(observed_state, tenant_id, resource_id, "observed")

        drift = self.drift_detector.compare(
            tenant_id=tenant_id,
            resource_id=resource_id,
            desired=expected_state,
            observed=observed_state,
        )
        checks = ["receipt_present", "tenant_scope", "resource_scope"]
        safe_receipt = receipt.simulation and not receipt.credentials_issued and receipt.network_calls == 0 and receipt.status == "dispatched"
        checks.append("simulation_constraints" if safe_receipt else "simulation_constraints_failed")
        checks.append("desired_state_match" if not drift.drifted else "post_change_drift_detected")
        verified = safe_receipt and not drift.drifted
        return VerificationReport(
            verification_id=uuid4(),
            receipt_id=receipt.receipt_id,
            tenant_id=tenant_id,
            resource_id=resource_id,
            verified=verified,
            checks=tuple(checks),
            rollback_required=not verified,
        )

    @staticmethod
    def _assert_state_scope(state: dict[str, Any], tenant_id: str, resource_id: str, label: str) -> None:
        if not isinstance(state, dict):
            raise ValueError(f"{label} state must be an object")
        state_tenant = state.get("tenant_id")
        state_resource = state.get("resource_id")
        if state_tenant is not None and state_tenant != tenant_id:
            raise PermissionError(f"{label} state crosses tenant boundary")
        if state_resource is not None and state_resource != resource_id:
            raise PermissionError(f"{label} state targets a different resource")

