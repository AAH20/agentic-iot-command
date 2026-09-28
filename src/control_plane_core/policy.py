from __future__ import annotations

from .models import AuthorizationRequest, PolicyDecision


FORBIDDEN_CAPABILITIES = frozenset(
    {
        "cloud_credentials",
        "host_filesystem",
        "privileged_process",
        "secrets",
        "ssh_agent_forwarding",
        "browser_profile",
        "rdp",
    }
)


class PolicyEngine:
    """Conservative policy engine for the local reference implementation."""

    def evaluate(self, request: AuthorizationRequest) -> PolicyDecision:
        reasons: list[str] = []
        requested_capabilities = set(request.capabilities)
        if not request.actor_id.strip():
            reasons.append("identity_missing")
        if not request.target.strip():
            reasons.append("target_missing")
        if not request.action.strip():
            reasons.append("intent_missing")
        if request.environment == "regulated":
            reasons.append("regulated_boundary_requires_separate_control_plane")
        if request.mode == "observe":
            if request.capabilities:
                reasons.append("observation_capabilities_must_be_empty")
            return self._decision(request, reasons, allow=not reasons)
        if request.mode == "plan":
            if requested_capabilities & FORBIDDEN_CAPABILITIES:
                reasons.append("expanded_capability_not_allowed_in_local_core")
            return self._decision(request, reasons, allow=not reasons)
        if request.mode != "mutate":
            reasons.append("unknown_mode")
            return self._decision(request, reasons, allow=False)
        if not request.approvals:
            reasons.append("approval_required")
        if request.environment == "production" and not request.second_approver:
            reasons.append("second_approver_required")
        if requested_capabilities & FORBIDDEN_CAPABILITIES:
            reasons.append("expanded_capability_requires_isolated_runner")
        if reasons:
            return self._decision(request, reasons, allow=False)
        return self._decision(request, ["approved_scoped_mutation"], allow=True)

    @staticmethod
    def _decision(request: AuthorizationRequest, reasons: list[str], *, allow: bool) -> PolicyDecision:
        return PolicyDecision(
            request_id=request.request_id,
            decision="allow" if allow else "deny",
            reason_codes=tuple(reasons or ["policy_denied"]),
            execution_permitted=allow and request.mode == "mutate" and request.environment != "regulated",
        )
