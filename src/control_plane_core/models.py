from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

Environment = Literal["lab", "development", "staging", "production", "regulated"]
Mode = Literal["observe", "plan", "mutate"]
Decision = Literal["allow", "deny", "conditional"]


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: UUID
    actor_id: str
    action: str
    target: str
    environment: Environment
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    mode: Mode = "observe"
    approvals: tuple[str, ...] = field(default_factory=tuple)
    second_approver: bool = False
    reason: str = ""
    tenant_id: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    request_id: UUID
    decision: Decision
    reason_codes: tuple[str, ...]
    execution_permitted: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "request_id": str(self.request_id),
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "execution_permitted": self.execution_permitted,
        }
