from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from .lifecycle import ChangeLifecycle, ExecutionReceipt


FORBIDDEN_SCOPES = frozenset({"secrets", "cloud_credentials", "host_filesystem", "ssh_agent_forwarding", "rdp"})


@dataclass(frozen=True)
class CapabilityToken:
    token_id: UUID
    plan_id: UUID
    scope: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    environment: str
    simulation: bool = True
    secret_material: bool = False

    def valid_at(self, moment: datetime | None = None) -> bool:
        current = moment or datetime.now(timezone.utc)
        return self.issued_at <= current < self.expires_at


@dataclass(frozen=True)
class RunnerRequest:
    request_id: UUID
    plan_id: UUID
    runner_type: str
    environment: str
    capability_token_id: UUID
    simulation: bool = True
    network_allowed: bool = False
    credentials_allowed: bool = False


@dataclass(frozen=True)
class SimulatedDispatch:
    runner_request: RunnerRequest
    capability_token: CapabilityToken
    execution_receipt: ExecutionReceipt


class CapabilityBroker:
    def issue(self, *, plan_id: UUID, environment: str, scope: tuple[str, ...], ttl_seconds: int = 600) -> CapabilityToken:
        if environment not in {"lab", "development"}:
            raise PermissionError("capability tokens are disabled outside lab/development")
        if not scope or set(scope) & FORBIDDEN_SCOPES:
            raise PermissionError("requested scope is outside the local simulation profile")
        if ttl_seconds < 1 or ttl_seconds > 900:
            raise ValueError("simulation capability TTL must be between 1 and 900 seconds")
        issued = datetime.now(timezone.utc)
        return CapabilityToken(
            token_id=uuid4(),
            plan_id=plan_id,
            scope=tuple(sorted(set(scope))),
            issued_at=issued,
            expires_at=issued + timedelta(seconds=ttl_seconds),
            environment=environment,
        )


class CredentialBroker:
    def issue(self, *, tenant_id: str, target: str, capability: str, environment: str) -> None:
        raise PermissionError("real credential issuance is disabled in the local reference core")


class ExecutionOrchestrator:
    def __init__(self, capability_broker: CapabilityBroker | None = None) -> None:
        self.capability_broker = capability_broker or CapabilityBroker()

    def dispatch_simulated(self, lifecycle: ChangeLifecycle, *, runner_type: str = "sandbox", scope: tuple[str, ...] = ("plan.read",)) -> SimulatedDispatch:
        if lifecycle.state != "approved":
            raise RuntimeError(f"dispatch requires approved lifecycle, got {lifecycle.state}")
        token = self.capability_broker.issue(plan_id=lifecycle.plan_id, environment=lifecycle.request.environment, scope=scope)
        runner_request = RunnerRequest(
            request_id=lifecycle.request.request_id,
            plan_id=lifecycle.plan_id,
            runner_type=runner_type,
            environment=lifecycle.request.environment,
            capability_token_id=token.token_id,
        )
        receipt = lifecycle.dispatch_simulated()
        return SimulatedDispatch(runner_request=runner_request, capability_token=token, execution_receipt=receipt)
