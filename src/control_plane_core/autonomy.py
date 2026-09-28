from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import re

from .impact_assessments import VerifiedImpactAssessment


class ActionRisk(StrEnum):
    ROUTINE = "routine"
    HIGH_IMPACT = "high_impact"
    DESTRUCTIVE = "destructive"
    PROVISION = "provision"
    DECOMMISSION = "decommission"
    SECURITY_BOUNDARY = "security_boundary"


class AutonomyDisposition(StrEnum):
    AUTO_ELIGIBLE = "auto_eligible"
    APPROVAL_REQUIRED = "approval_required"
    DENY = "deny"


@dataclass(frozen=True)
class OperationContract:
    """Trusted adapter metadata; never accept these flags from an agent plan."""

    action_id: str
    risk: ActionRisk
    idempotent: bool
    reversible: bool
    rollback_supported: bool
    verification_supported: bool
    uses_privileged_identity: bool = False
    crosses_security_boundary: bool = False


@dataclass(frozen=True)
class AutonomyRule:
    """Exact allowlist entry for a standing, operator-approved policy."""

    action_id: str
    target_ids: tuple[str, ...]
    environments: tuple[str, ...]
    max_targets_per_run: int = 1
    max_batch_size: int = 1
    enabled: bool = False
    max_affected_resources: int = 1
    max_estimated_cost_microusd: int = 0


@dataclass(frozen=True)
class MaintenanceWindow:
    window_id: str
    action_id: str
    target_ids: tuple[str, ...]
    environments: tuple[str, ...]
    starts_at: datetime
    ends_at: datetime


@dataclass(frozen=True)
class AutonomyProfile:
    profile_id: str
    tenant_id: str
    expires_at: datetime
    rules: tuple[AutonomyRule, ...] = ()
    verified_signature: bool = False
    revoked: bool = False
    max_concurrency: int = 1
    max_total_targets: int = 1
    denied_actions: tuple[str, ...] = ()
    enabled: bool = False
    policy_digest: str = ""
    max_affected_resources: int = 1
    max_estimated_cost_microusd: int = 0
    maintenance_windows: tuple[MaintenanceWindow, ...] = ()
    signed_record: dict[str, object] | None = None


@dataclass(frozen=True)
class AutonomyRequest:
    tenant_id: str
    action_id: str
    target_ids: tuple[str, ...]
    environment: str
    batch_size: int = 1
    active_concurrency: int = 0
    plan_digest: str = ""
    task_id: str = ""
    max_runtime_seconds: int = 1
    impact_assessment: VerifiedImpactAssessment | None = None


@dataclass(frozen=True)
class AutonomyDecision:
    disposition: AutonomyDisposition
    reason_codes: tuple[str, ...]
    profile_id: str
    action_id: str
    target_ids: tuple[str, ...]
    plan_digest: str
    policy_digest: str = ""
    impact_assessment_digest: str = ""
    # This evaluator classifies policy only. A separate authorized dispatcher
    # must verify the signed plan, current state, lease, and runtime controls.
    execution_permitted: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "disposition": self.disposition.value,
            "reason_codes": list(self.reason_codes),
            "profile_id": self.profile_id,
            "action_id": self.action_id,
            "target_ids": list(self.target_ids),
            "plan_digest": self.plan_digest,
            "policy_digest": self.policy_digest,
            "impact_assessment_digest": self.impact_assessment_digest,
            "execution_permitted": self.execution_permitted,
        }


HIGH_RISK = frozenset({
    ActionRisk.HIGH_IMPACT,
    ActionRisk.DESTRUCTIVE,
    ActionRisk.PROVISION,
    ActionRisk.DECOMMISSION,
    ActionRisk.SECURITY_BOUNDARY,
})


class AutonomyPolicyEngine:
    """Classify whether a signed standing policy could authorize a routine action.

    This is a policy decision point, not an executor. Even AUTO_ELIGIBLE returns
    `execution_permitted=False`; task-scoped lease checks, canary orchestration,
    health gates, idempotency storage, and runner isolation are still required.
    """

    def evaluate(
        self,
        profile: AutonomyProfile,
        request: AutonomyRequest,
        contract: OperationContract | None,
        *,
        now: datetime | None = None,
    ) -> AutonomyDecision:
        reasons: list[str] = []
        assessment_digest = ""

        def decision(disposition: AutonomyDisposition, *codes: str) -> AutonomyDecision:
            return AutonomyDecision(
                disposition=disposition,
                reason_codes=tuple(codes),
                profile_id=profile.profile_id,
                action_id=request.action_id,
                target_ids=request.target_ids,
                plan_digest=request.plan_digest,
                policy_digest=profile.policy_digest,
                impact_assessment_digest=assessment_digest,
            )

        if profile.revoked:
            return decision(AutonomyDisposition.DENY, "autonomy_profile_revoked")
        if not profile.enabled:
            return decision(AutonomyDisposition.DENY, "autonomy_profile_disabled")
        current = now or datetime.now(timezone.utc)
        if profile.expires_at.tzinfo is None or current >= profile.expires_at:
            return decision(AutonomyDisposition.DENY, "autonomy_profile_expired_or_invalid")
        if request.tenant_id != profile.tenant_id or not request.tenant_id:
            return decision(AutonomyDisposition.DENY, "tenant_scope_mismatch")
        if request.action_id in profile.denied_actions:
            return decision(AutonomyDisposition.DENY, "action_explicitly_denied")
        if contract is None or contract.action_id != request.action_id:
            return decision(AutonomyDisposition.DENY, "unknown_or_mismatched_operation_contract")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", request.plan_digest):
            return decision(AutonomyDisposition.DENY, "plan_digest_missing_or_malformed")
        if not request.target_ids or any(not target.strip() for target in request.target_ids):
            return decision(AutonomyDisposition.DENY, "target_scope_missing")
        if len(set(request.target_ids)) != len(request.target_ids):
            return decision(AutonomyDisposition.DENY, "duplicate_target_in_plan")
        if profile.max_concurrency < 1 or profile.max_total_targets < 1:
            return decision(AutonomyDisposition.DENY, "invalid_profile_limits")
        if (isinstance(profile.max_affected_resources, bool) or not isinstance(profile.max_affected_resources, int)
                or profile.max_affected_resources < 1
                or isinstance(profile.max_estimated_cost_microusd, bool)
                or not isinstance(profile.max_estimated_cost_microusd, int)
                or profile.max_estimated_cost_microusd < 0):
            return decision(AutonomyDisposition.DENY, "invalid_profile_impact_limits")
        if request.active_concurrency < 0:
            return decision(AutonomyDisposition.DENY, "invalid_active_concurrency")
        if request.active_concurrency >= profile.max_concurrency:
            return decision(AutonomyDisposition.APPROVAL_REQUIRED, "concurrency_limit_reached")
        if len(request.target_ids) > profile.max_total_targets:
            return decision(AutonomyDisposition.APPROVAL_REQUIRED, "profile_target_limit_exceeded")
        if request.action_id in {"*", "shell.exec", "command.run"}:
            return decision(AutonomyDisposition.DENY, "generic_command_operation_forbidden")

        rule = next((item for item in profile.rules if item.action_id == request.action_id and item.enabled), None)
        if rule is None:
            return decision(AutonomyDisposition.APPROVAL_REQUIRED, "no_enabled_standing_rule")
        if len([item for item in profile.rules if item.action_id == request.action_id and item.enabled]) != 1:
            return decision(AutonomyDisposition.DENY, "ambiguous_standing_rules")
        if (isinstance(rule.max_affected_resources, bool) or not isinstance(rule.max_affected_resources, int)
                or rule.max_affected_resources < 1
                or isinstance(rule.max_estimated_cost_microusd, bool)
                or not isinstance(rule.max_estimated_cost_microusd, int)
                or rule.max_estimated_cost_microusd < 0):
            return decision(AutonomyDisposition.DENY, "invalid_rule_impact_limits")
        if not profile.verified_signature:
            reasons.append("standing_policy_signature_not_verified")
        if not re.fullmatch(r"[0-9a-f]{64}", profile.policy_digest):
            reasons.append("standing_policy_digest_missing_or_malformed")
        if contract.risk in HIGH_RISK:
            reasons.append("high_impact_action_requires_human_approval")
        if not contract.idempotent:
            reasons.append("operation_not_idempotent")
        if not contract.reversible or not contract.rollback_supported:
            reasons.append("operation_lacks_verified_rollback")
        if not contract.verification_supported:
            reasons.append("operation_lacks_postcondition_verification")
        if contract.uses_privileged_identity:
            reasons.append("privileged_identity_excluded_from_auto_execution")
        if contract.crosses_security_boundary:
            reasons.append("security_boundary_change_requires_approval")
        if request.environment not in rule.environments or request.environment in {"production", "regulated"}:
            reasons.append("environment_not_eligible_for_autonomy")
        if not set(request.target_ids).issubset(set(rule.target_ids)):
            reasons.append("target_not_in_exact_allowlist")
        if rule.max_targets_per_run < 1 or len(request.target_ids) > rule.max_targets_per_run:
            reasons.append("rule_target_limit_exceeded")
        if rule.max_batch_size < 1 or request.batch_size < 1 or request.batch_size > rule.max_batch_size:
            reasons.append("batch_limit_exceeded")
        assessment = request.impact_assessment
        if assessment is None:
            reasons.append("trusted_impact_estimate_missing_or_invalid")
        elif (not isinstance(assessment, VerifiedImpactAssessment)
              or assessment.tenant_id != request.tenant_id
              or assessment.task_id != request.task_id
              or assessment.operation_id != request.action_id
              or assessment.target_ids != request.target_ids
              or assessment.environment != request.environment
              or assessment.plan_digest != request.plan_digest
              or isinstance(assessment.affected_resource_count, bool)
              or not isinstance(assessment.affected_resource_count, int)
              or assessment.affected_resource_count < 0
              or isinstance(assessment.estimated_cost_microusd, bool)
              or not isinstance(assessment.estimated_cost_microusd, int)
              or assessment.estimated_cost_microusd < 0
              or not isinstance(assessment.expires_at, datetime)
              or assessment.expires_at.tzinfo is None
              or current >= assessment.expires_at
              or not isinstance(assessment.assessment_digest, str)
              or not re.fullmatch(r"[0-9a-f]{64}", assessment.assessment_digest)):
            reasons.append("trusted_impact_estimate_missing_or_invalid")
        else:
            assessment_digest = assessment.assessment_digest
            if (assessment.affected_resource_count > profile.max_affected_resources
                    or assessment.affected_resource_count > rule.max_affected_resources):
                reasons.append("affected_resource_limit_exceeded")
            if (assessment.estimated_cost_microusd > profile.max_estimated_cost_microusd
                    or assessment.estimated_cost_microusd > rule.max_estimated_cost_microusd):
                reasons.append("estimated_cost_limit_exceeded")
        if (isinstance(request.max_runtime_seconds, bool)
                or not isinstance(request.max_runtime_seconds, int)
                or not 1 <= request.max_runtime_seconds <= 1800):
            reasons.append("invalid_task_runtime_bound")
        matching_windows = [
            window for window in profile.maintenance_windows
            if window.action_id == request.action_id
            and request.environment in window.environments
            and set(request.target_ids).issubset(set(window.target_ids))
            and window.starts_at <= current < window.ends_at
        ]
        if not matching_windows:
            reasons.append("approved_maintenance_window_not_open")
        elif len(matching_windows) > 1:
            reasons.append("ambiguous_maintenance_windows")
        elif (isinstance(request.max_runtime_seconds, int)
              and current.timestamp() + request.max_runtime_seconds > matching_windows[0].ends_at.timestamp()):
            reasons.append("action_would_outlive_maintenance_window")

        if reasons:
            return decision(AutonomyDisposition.APPROVAL_REQUIRED, *reasons)
        return decision(AutonomyDisposition.AUTO_ELIGIBLE, "signed_bounded_routine_rule_matches")
