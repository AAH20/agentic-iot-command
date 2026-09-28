from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class WorkloadIdentityRequest:
    request_id: UUID
    agent_id: str
    tenant_id: str
    target: str
    capabilities: tuple[str, ...]
    environment: str
    expires_in_seconds: int


@dataclass(frozen=True)
class WorkloadIdentityDecision:
    request_id: UUID
    decision: str
    reason_codes: tuple[str, ...]
    credential_issued: bool = False


class WorkloadIdentityBroker:
    """Provider-neutral workload identity boundary; never mints credentials locally."""

    def evaluate(self, request: WorkloadIdentityRequest) -> WorkloadIdentityDecision:
        reasons: list[str] = []
        if request.environment in {"production", "regulated"}:
            reasons.append("environment_requires_external_iam_and_approval")
        if request.expires_in_seconds > 900 or request.expires_in_seconds < 1:
            reasons.append("expiry_out_of_bounds")
        if not request.capabilities:
            reasons.append("capability_scope_missing")
        reasons.append("credential_minting_disabled_in_local_core")
        return WorkloadIdentityDecision(request.request_id, "deny", tuple(reasons), credential_issued=False)


@dataclass(frozen=True)
class SessionEvent:
    event_id: UUID
    session_id: UUID
    event_type: str
    tenant_id: str
    identity_id: str
    target: str
    occurred_at: str
    credentials_exposed: bool = False
    reason_codes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "session_id": str(self.session_id),
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "identity_id": self.identity_id,
            "target": self.target,
            "occurred_at": self.occurred_at,
            "credentials_exposed": self.credentials_exposed,
            "reason_codes": list(self.reason_codes),
        }


class SessionGateway:
    def __init__(self) -> None:
        self.events: list[SessionEvent] = []
        self._sessions: dict[UUID, tuple[str, str, str]] = {}

    def open(self, *, tenant_id: str, identity_id: str, target: str, approved: bool) -> SessionEvent:
        if not approved:
            event = self._event(uuid4(), "denied", tenant_id, identity_id, target, ("approval_required",))
            self.events.append(event)
            raise PermissionError("session approval is required")
        session_id = uuid4()
        self._sessions[session_id] = (tenant_id, identity_id, target)
        event = self._event(session_id, "opened", tenant_id, identity_id, target, ("session_recorded",))
        self.events.append(event)
        return event

    def close(self, *, session_id: UUID, tenant_id: str) -> SessionEvent:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError("session not found")
        stored_tenant, identity_id, target = session
        if stored_tenant != tenant_id:
            raise PermissionError("session crosses tenant boundary")
        del self._sessions[session_id]
        event = self._event(session_id, "closed", tenant_id, identity_id, target, ("session_closed",))
        self.events.append(event)
        return event

    @staticmethod
    def _event(session_id: UUID, event_type: str, tenant_id: str, identity_id: str, target: str, reasons: tuple[str, ...]) -> SessionEvent:
        return SessionEvent(uuid4(), session_id, event_type, tenant_id, identity_id, target, _now().isoformat().replace("+00:00", "Z"), False, reasons)


@dataclass(frozen=True)
class BreakGlassDecision:
    request_id: UUID
    decision: str
    reason_codes: tuple[str, ...]
    expires_at: str | None
    post_review_required: bool = True
    credential_issued: bool = False


class BreakGlassService:
    def evaluate(self, *, request_id: UUID, tenant_id: str, requester_id: str, target: str, reason: str, approver_ids: tuple[str, ...], expires_in_seconds: int, environment: str) -> BreakGlassDecision:
        reasons: list[str] = []
        if not tenant_id or not requester_id or not target or not reason:
            reasons.append("required_context_missing")
        if len(set(approver_ids)) < 2:
            reasons.append("dual_approval_required")
        if expires_in_seconds < 1 or expires_in_seconds > 900:
            reasons.append("expiry_out_of_bounds")
        if environment == "regulated":
            reasons.append("regulated_boundary_requires_separate_authority")
        if reasons:
            return BreakGlassDecision(request_id, "deny", tuple(reasons), None)
        expires_at = (_now() + timedelta(seconds=expires_in_seconds)).isoformat().replace("+00:00", "Z")
        return BreakGlassDecision(request_id, "conditional", ("dual_approval_recorded", "post_review_required", "credential_minting_disabled"), expires_at)
