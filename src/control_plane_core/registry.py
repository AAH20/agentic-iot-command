from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID, uuid4

from .models import AuthorizationRequest
from .service import ControlPlane


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    approver_id: str
    tenant_id: str
    signature_verified: bool
    expires_at: str
    plan_id: str = ""


class LocalControlPlaneStore:
    """In-memory Phase 1 bounded context; no external side effects."""

    def __init__(self, control_plane: ControlPlane | None = None) -> None:
        self.control_plane = control_plane or ControlPlane.local()
        self.tenants: dict[str, dict[str, Any]] = {}
        self.identities: dict[str, dict[str, Any]] = {}
        self.assets: dict[str, dict[str, Any]] = {}
        self.requests: dict[str, AuthorizationRequest] = {}
        self.plans: dict[str, dict[str, Any]] = {}
        self.approvals: dict[str, ApprovalRecord] = {}

    def create_tenant(self, tenant_id: str, name: str) -> dict[str, Any]:
        self._required(tenant_id, "tenant_id")
        self._required(name, "name")
        if tenant_id in self.tenants:
            raise ValueError("tenant already exists")
        record = {"tenant_id": tenant_id, "name": name, "status": "active"}
        self.tenants[tenant_id] = record
        return record

    def register_identity(self, identity_id: str, tenant_id: str, kind: str) -> dict[str, Any]:
        self._require_tenant(tenant_id)
        self._required(identity_id, "identity_id")
        self._required(kind, "kind")
        if identity_id in self.identities:
            raise ValueError("identity already exists")
        record = {"identity_id": identity_id, "tenant_id": tenant_id, "kind": kind, "status": "active"}
        self.identities[identity_id] = record
        return record

    def register_asset(self, asset_id: str, tenant_id: str, kind: str, environment: str) -> dict[str, Any]:
        self._require_tenant(tenant_id)
        self._required(asset_id, "asset_id")
        self._required(kind, "kind")
        self._required(environment, "environment")
        if asset_id in self.assets:
            raise ValueError("asset already exists")
        record = {"asset_id": asset_id, "tenant_id": tenant_id, "kind": kind, "environment": environment, "status": "observed"}
        self.assets[asset_id] = record
        return record

    def create_request(self, request: AuthorizationRequest) -> dict[str, Any]:
        self._require_tenant(request.tenant_id)
        identity = self.identities.get(request.actor_id)
        if identity is None or identity["tenant_id"] != request.tenant_id:
            raise ValueError("actor identity is missing or crosses tenant boundary")
        self.assert_asset_scope(request.tenant_id, request.target, request.environment)
        request_id = str(request.request_id)
        self.requests[request_id] = request
        decision = self.control_plane.authorize(request)
        return {"request_id": request_id, "tenant_id": request.tenant_id, "decision": decision.as_dict()}

    def create_plan(self, request_id: str) -> dict[str, Any]:
        request = self.requests.get(request_id)
        if request is None:
            raise KeyError("authorization request not found")
        plan = self.control_plane.change_plan(request)
        self.plans[plan["plan_id"]] = plan
        return plan

    def record_approval(self, record: ApprovalRecord) -> dict[str, Any]:
        request = self.requests.get(record.request_id)
        approver = self.identities.get(record.approver_id)
        if request is None:
            raise KeyError("authorization request not found")
        if approver is None or approver["tenant_id"] != record.tenant_id or request.tenant_id != record.tenant_id:
            raise ValueError("approval crosses tenant boundary")
        if not record.signature_verified:
            raise ValueError("approval signature must be verified before recording")
        if record.approval_id in self.approvals:
            raise ValueError("approval already exists")
        self.approvals[record.approval_id] = record
        return asdict(record)

    def assert_asset_scope(self, tenant_id: str, asset_id: str, environment: str) -> None:
        self._require_tenant(tenant_id)
        asset = self.assets.get(asset_id)
        if asset is None or asset["tenant_id"] != tenant_id:
            raise ValueError("target asset is missing or crosses tenant boundary")
        if asset["environment"] != environment:
            raise ValueError("target environment does not match asset")

    def assert_tenant(self, tenant_id: str) -> None:
        """Validate that a local API operation belongs to a registered tenant."""
        self._require_tenant(tenant_id)

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "execution": "disabled",
            "credentials": "disabled",
            "network": "disabled",
            "counts": {"tenants": len(self.tenants), "identities": len(self.identities), "assets": len(self.assets), "requests": len(self.requests), "plans": len(self.plans), "approvals": len(self.approvals)},
        }

    def _require_tenant(self, tenant_id: str) -> None:
        self._required(tenant_id, "tenant_id")
        if tenant_id not in self.tenants:
            raise KeyError("tenant not found")

    @staticmethod
    def _required(value: str, name: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")
