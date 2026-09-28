from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from .models import AuthorizationRequest, PolicyDecision
from .policy import PolicyEngine


@dataclass(frozen=True)
class ControlPlane:
    policy: PolicyEngine

    @classmethod
    def local(cls) -> "ControlPlane":
        return cls(policy=PolicyEngine())

    def authorize(self, request: AuthorizationRequest) -> PolicyDecision:
        """Evaluate a request without executing it or minting credentials."""
        return self.policy.evaluate(request)

    def change_plan(self, request: AuthorizationRequest) -> dict[str, object]:
        decision = self.authorize(request)
        return {
            "plan_id": str(uuid4()),
            "request_id": str(request.request_id),
            "decision": decision.decision,
            "reason_codes": list(decision.reason_codes),
            "steps": [f"observe target {request.target}", "obtain required approval", "execute in isolated runner"],
            "rollback": ["restore the pre-change state", "verify health and policy"],
            "blast_radius": "unknown" if request.mode == "mutate" else "none",
            "execution_permitted": decision.execution_permitted,
        }


def request(*, actor_id: str, action: str, target: str, environment: str = "lab", mode: str = "observe", capabilities: tuple[str, ...] = (), approvals: tuple[str, ...] = (), second_approver: bool = False, tenant_id: str = "") -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id=UUID(str(uuid4())),
        actor_id=actor_id,
        action=action,
        target=target,
        environment=environment,  # type: ignore[arg-type]
        mode=mode,  # type: ignore[arg-type]
        capabilities=capabilities,
        approvals=approvals,
        second_approver=second_approver,
        tenant_id=tenant_id,
    )
