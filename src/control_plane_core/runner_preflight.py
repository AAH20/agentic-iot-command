from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .autonomy_catalog import TRUSTED_OPERATION_CONTRACTS, validate_operation_plan
from .execution_grants import ExecutionGrantVerifier


class AuthenticatedLeaseSource(Protocol):
    """Runner identity-bound channel to the authoritative lease service.

    A production implementation must authenticate the runner with a dedicated
    workload identity over mutually authenticated TLS, validate the server
    identity, and return the current record directly from the authoritative
    journal. It must not accept a lease snapshot supplied by a task submitter.
    """

    def get_current_execution_lease(self, *, task_id: str, runner_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class VerifiedExecutionPreflight:
    """In-memory authorization evidence; intentionally not an executor token."""

    task_id: str
    tenant_id: str
    target_id: str
    operation_id: str
    environment: str
    plan_digest: str
    grant_digest: str
    grant_expires_at: datetime
    max_runtime_seconds: int
    plan: dict[str, Any]


class RunnerPreflight:
    """Validate a signed grant against fresh authoritative lease state.

    This class does not dispatch an operation, consume a one-shot execution
    permit, issue credentials, or make execution permissible. It is a required
    worker-side gate primitive, not a complete runner.
    """

    _LEASE_FIELDS = {
        "task_id", "tenant_id", "target_id", "operation_id", "environment",
        "plan_digest", "authorization_mode", "authorization_id", "approval_id",
        "policy_digest", "impact_assessment_digest", "lease_generation", "runner_id",
        "lease_token", "status", "lease_stage", "lease_until", "plan",
    }

    def __init__(self, *, lease_source: AuthenticatedLeaseSource,
                 grant_verifier: ExecutionGrantVerifier) -> None:
        self.lease_source = lease_source
        self.grant_verifier = grant_verifier

    def verify(self, envelope: dict[str, Any], *, task_id: str,
               authenticated_runner_id: str) -> VerifiedExecutionPreflight:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be a specific identifier")
        if (not isinstance(authenticated_runner_id, str) or not authenticated_runner_id.strip()
                or len(authenticated_runner_id) > 256 or authenticated_runner_id == "*"):
            raise PermissionError("runner identity must be authenticated and specific")

        lease = self.lease_source.get_current_execution_lease(
            task_id=task_id, runner_id=authenticated_runner_id,
        )
        if not isinstance(lease, dict) or set(lease) != self._LEASE_FIELDS:
            raise PermissionError("authoritative lease record is incomplete or has unexpected fields")
        if lease["task_id"] != task_id or lease["runner_id"] != authenticated_runner_id:
            raise PermissionError("current lease is outside the authenticated runner scope")
        if lease["status"] != "leased" or lease["lease_stage"] != "execution":
            raise PermissionError("task has no active execution lease")
        if not isinstance(lease["lease_token"], str) or not lease["lease_token"]:
            raise PermissionError("current lease token is unavailable")
        lease_until = _timestamp(lease["lease_until"])
        now = datetime.now(timezone.utc)
        if lease_until <= now:
            raise PermissionError("execution lease has expired")

        plan = lease["plan"]
        if not isinstance(plan, dict):
            raise PermissionError("authoritative task plan is unavailable")
        canonical_plan = json.dumps(
            plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        plan_digest = hashlib.sha256(canonical_plan).hexdigest()
        if plan_digest != lease["plan_digest"]:
            raise PermissionError("authoritative plan digest does not match its contents")
        if (plan.get("operation_id") != lease["operation_id"]
                or plan.get("target_ids") != [lease["target_id"]]
                or plan.get("environment") != lease["environment"]):
            raise PermissionError("authoritative plan scope does not match its execution lease")
        if lease["operation_id"] not in TRUSTED_OPERATION_CONTRACTS:
            raise PermissionError("operation is not present in the code-owned runner catalog")
        plan_runtime = plan.get("max_runtime_seconds")
        if (plan.get("schema_version") != "a2z-task-plan-v1"
                or isinstance(plan_runtime, bool) or not isinstance(plan_runtime, int)
                or not 1 <= plan_runtime <= 1800):
            raise PermissionError("authoritative task plan has an invalid schema or runtime bound")
        reasons = validate_operation_plan(lease["operation_id"], plan)
        if reasons:
            raise PermissionError("operation plan failed code-owned validation: " + ",".join(reasons))

        expected_claims = {
            "task_id": lease["task_id"], "tenant_id": lease["tenant_id"],
            "target_id": lease["target_id"], "operation_id": lease["operation_id"],
            "environment": lease["environment"], "plan_digest": lease["plan_digest"],
            "authorization_mode": lease["authorization_mode"],
            "authorization_id": lease["authorization_id"],
            "approval_id": lease["approval_id"],
            "policy_digest": lease["policy_digest"],
            "impact_assessment_digest": lease["impact_assessment_digest"],
            "lease_generation": lease["lease_generation"],
            "runner_id": lease["runner_id"],
            "lease_token_sha256": hashlib.sha256(lease["lease_token"].encode("utf-8")).hexdigest(),
        }
        grant, grant_digest = self.grant_verifier.verify(envelope, expected_claims=expected_claims)
        grant_expires_at = _timestamp(grant["expires_at"])
        if grant_expires_at > lease_until:
            raise PermissionError("execution grant outlives its current lease")
        if grant["max_runtime_seconds"] > plan["max_runtime_seconds"]:
            raise PermissionError("execution grant exceeds the task plan runtime")
        return VerifiedExecutionPreflight(
            task_id=lease["task_id"], tenant_id=lease["tenant_id"],
            target_id=lease["target_id"], operation_id=lease["operation_id"],
            environment=lease["environment"], plan_digest=plan_digest,
            grant_digest=grant_digest, grant_expires_at=grant_expires_at,
            max_runtime_seconds=grant["max_runtime_seconds"], plan=plan,
        )


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise PermissionError("lease or grant timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PermissionError("lease or grant timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise PermissionError("lease or grant timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)
