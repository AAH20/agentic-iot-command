from __future__ import annotations

from types import MappingProxyType

from .autonomy import ActionRisk, OperationContract


# This catalog is code-owned. No task, model response, or MCP caller can lower
# an operation's risk or assert its rollback/verification properties.
TRUSTED_OPERATION_CONTRACTS = MappingProxyType({
    "virtualbox.vm.set_demo_description": OperationContract(
        action_id="virtualbox.vm.set_demo_description", risk=ActionRisk.ROUTINE,
        idempotent=True, reversible=True, rollback_supported=True,
        verification_supported=True,
    ),
    "virtualbox.vm.start": OperationContract(
        action_id="virtualbox.vm.start", risk=ActionRisk.HIGH_IMPACT,
        idempotent=True, reversible=True, rollback_supported=True,
        verification_supported=True,
    ),
    "virtualbox.vm.acpi_shutdown": OperationContract(
        action_id="virtualbox.vm.acpi_shutdown", risk=ActionRisk.HIGH_IMPACT,
        idempotent=True, reversible=True, rollback_supported=True,
        verification_supported=True,
    ),
})


DEMO_DESCRIPTION = "A2Z-Control-Plane-Demo"
DEMO_DESCRIPTION_INITIAL = "A2Z-Control-Plane-Unlabeled"


def validate_operation_plan(operation_id: str, plan: dict) -> tuple[str, ...]:
    """Code-owned narrow plan checks required before risk evaluation."""
    if operation_id != "virtualbox.vm.set_demo_description":
        return ()
    if not isinstance(plan, dict):
        return ("typed_plan_required",)
    pre = plan.get("preconditions")
    desired = plan.get("desired_state")
    rollback = plan.get("rollback")
    if plan.get("environment") != "lab" or not isinstance(plan.get("target_ids"), list) or len(plan["target_ids"]) != 1:
        return ("demo_description_requires_one_exact_lab_vm",)
    if not isinstance(pre, dict) or pre != {
        "power_state": "powered_off", "description": DEMO_DESCRIPTION_INITIAL,
    }:
        return ("demo_description_preconditions_must_be_exact",)
    if not isinstance(desired, dict) or desired != {"description": DEMO_DESCRIPTION}:
        return ("demo_description_desired_state_not_code_owned",)
    if not isinstance(rollback, dict) or rollback != {"description": DEMO_DESCRIPTION_INITIAL}:
        return ("demo_description_rollback_must_restore_observed_value",)
    if isinstance(plan.get("max_runtime_seconds"), bool) or not isinstance(plan.get("max_runtime_seconds"), int) or not 1 <= plan["max_runtime_seconds"] <= 120:
        return ("demo_description_runtime_limit_exceeded",)
    return ()
