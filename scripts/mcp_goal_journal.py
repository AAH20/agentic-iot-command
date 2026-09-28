#!/usr/bin/env python3
"""Ubuntu-hosted stdio MCP gateway for durable, non-executing infrastructure goals."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from control_plane_core.goals import DurableGoalStore  # noqa: E402
from control_plane_core.approval import Ed25519ApprovalVerifier  # noqa: E402
from control_plane_core.autonomy import AutonomyPolicyEngine, AutonomyRequest  # noqa: E402
from control_plane_core.autonomy_catalog import TRUSTED_OPERATION_CONTRACTS, validate_operation_plan  # noqa: E402
from control_plane_core.autonomy_profiles import Ed25519AutonomyProfileVerifier, load_signed_autonomy_profile  # noqa: E402
from control_plane_core.impact_assessments import ImpactAssessmentVerifier  # noqa: E402


SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
INSTRUCTIONS = (
    "This MCP server submits goals, records typed task proposals, evaluates them against a verified signed policy, accepts separately signed "
    "task approvals or revalidated standing-policy decisions for queueing, and reads status. Queueing does not execute tasks. It does not observe or mutate hosts, run commands, "
    "approve critical actions itself, or start workers. The tenant, operator, and baseline "
    "guardrails come from owner-only config and cannot be changed by tool arguments. Policy evaluation is never execution authority. Never include secrets."
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def load_settings(config_path: Path, *, allow_user_owned_config: bool = False) -> tuple[DurableGoalStore, str, str, dict[str, Any], Any | None, Any | None, Any | None]:
    if config_path.is_symlink() or not config_path.is_file():
        raise PermissionError("goal MCP configuration must be a regular non-symlink file")
    config_stat = config_path.stat()
    if (not stat.S_ISREG(config_stat.st_mode) or stat.S_IMODE(config_stat.st_mode) & 0o027
            or not config_stat.st_mode & stat.S_IRUSR):
        raise PermissionError("goal gateway config must be root-owned/group-readable or owner-only and never group/other writable")
    if os.name == "posix" and config_stat.st_uid != 0 and not allow_user_owned_config:
        raise PermissionError("Ubuntu goal gateway config must be root-owned")
    if config_path.stat().st_size > 64 * 1024:
        raise ValueError("goal MCP config exceeds 64 KiB")
    config = json.loads(config_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    required = {"tenant_id", "requested_by", "database_path", "baseline_guardrails", "autonomy_profile_path", "trust_directory", "impact_trust_directory"}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError("goal MCP config fields must exactly match the documented contract")
    for key in ("tenant_id", "requested_by", "database_path"):
        if not isinstance(config[key], str) or not config[key].strip():
            raise ValueError(f"{key} must be a non-empty string")
    if not isinstance(config["baseline_guardrails"], dict):
        raise ValueError("baseline_guardrails must be a JSON object")
    guardrails = config["baseline_guardrails"]
    guardrail_fields = {"profile_id", "autonomy_enabled", "allowed_environments", "allowed_targets",
                        "critical_decisions", "production_mutations", "generic_shell"}
    if set(guardrails) != guardrail_fields:
        raise ValueError("baseline_guardrails fields do not match the fail-closed contract")
    if (not isinstance(guardrails["profile_id"], str) or not guardrails["profile_id"].strip()
            or not isinstance(guardrails["autonomy_enabled"], bool)
            or guardrails["critical_decisions"] != "operator_approval"
            or guardrails["production_mutations"] != "deny"
            or guardrails["generic_shell"] != "deny"):
        raise PermissionError("goal MCP baseline must keep autonomy disabled and critical/production/generic-shell actions gated")
    for field in ("allowed_environments", "allowed_targets"):
        values = guardrails[field]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values) or len(set(values)) != len(values):
            raise ValueError(f"{field} must be a unique array of non-empty strings")
    if not set(guardrails["allowed_environments"]).issubset({"lab", "development", "staging"}):
        raise PermissionError("the goal MCP baseline may only include lab, development, or staging")
    db = Path(config["database_path"]).expanduser()
    if not db.is_absolute():
        raise ValueError("database_path must be absolute")
    profile_path, trust_dir = config["autonomy_profile_path"], config["trust_directory"]
    profile = None
    autonomy_profile_verifier = None
    if profile_path is not None or trust_dir is not None:
        if not isinstance(profile_path, str) or not profile_path.strip() or not isinstance(trust_dir, str) or not trust_dir.strip():
            raise ValueError("autonomy_profile_path and trust_directory must be configured together")
        autonomy_profile_verifier = Ed25519AutonomyProfileVerifier(Path(trust_dir).expanduser())
        profile = load_signed_autonomy_profile(
            Path(profile_path).expanduser(), verifier=autonomy_profile_verifier,
        )
        if (profile.tenant_id != config["tenant_id"] or profile.profile_id != guardrails["profile_id"]
                or profile.enabled != guardrails["autonomy_enabled"]):
            raise PermissionError("verified autonomy profile does not match configured tenant, profile, or enabled state")
        if any(not set(rule.target_ids).issubset(set(guardrails["allowed_targets"]))
               or not set(rule.environments).issubset(set(guardrails["allowed_environments"])) for rule in profile.rules):
            raise PermissionError("signed autonomy profile exceeds the local target/environment guardrails")
    elif guardrails["autonomy_enabled"]:
        raise PermissionError("autonomy cannot be enabled without a verified signed profile")
    impact_trust = config["impact_trust_directory"]
    if impact_trust is not None and (not isinstance(impact_trust, str) or not impact_trust.strip()):
        raise ValueError("impact_trust_directory must be an absolute path or null")
    if impact_trust is not None and not Path(impact_trust).expanduser().is_absolute():
        raise ValueError("impact_trust_directory must be an absolute path or null")
    impact_verifier = ImpactAssessmentVerifier(Path(impact_trust).expanduser()) if impact_trust else None
    return (DurableGoalStore(db), config["tenant_id"], config["requested_by"], guardrails,
            profile, impact_verifier, autonomy_profile_verifier)


def _result(value: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}]}


def dispatch(message: dict[str, Any], *, store: DurableGoalStore, tenant_id: str,
             requested_by: str, baseline_guardrails: dict[str, Any], autonomy_profile: Any | None = None,
             approval_verifier: Any | None = None, impact_verifier: Any | None = None,
             autonomy_profile_verifier: Any | None = None) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})
    if not isinstance(method, str):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "invalid request"}}
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        protocol = requested if requested in SUPPORTED_PROTOCOLS else "2025-03-26"
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "a2z-goal-journal", "version": "0.1.0"},
            "instructions": INSTRUCTIONS,
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [
            {
                "name": "submit_infrastructure_goal",
                "description": "Persist an operator-authorized outcome request. Uses immutable tenant/operator/baseline guardrails from local config. Does not execute or authorize changes.",
                "inputSchema": {"type": "object", "properties": {
                    "objective": {"type": "string", "minLength": 1, "maxLength": 5000},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
                }, "required": ["objective", "idempotency_key"], "additionalProperties": False},
            },
            {
                "name": "propose_infrastructure_task",
                "description": "Persist a typed task and full plan artifact within configured non-production environment and exact target allowlists. Ubuntu validates and hashes the plan; it remains pending_policy and cannot execute.",
                "inputSchema": {"type": "object", "properties": {
                    "goal_id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "operation_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "target_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 256}},
                    "environment": {"type": "string", "enum": ["lab", "development", "staging"]},
                    "plan": {"type": "object", "properties": {
                        "schema_version": {"const": "a2z-task-plan-v1"},
                        "operation_id": {"type": "string", "minLength": 1},
                        "target_ids": {"type": "array", "minItems": 1, "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
                        "environment": {"type": "string", "enum": ["lab", "development", "staging"]},
                        "preconditions": {"type": "object", "minProperties": 1},
                        "desired_state": {"type": "object", "minProperties": 1},
                        "rollback": {"type": "object", "minProperties": 1},
                        "max_runtime_seconds": {"type": "integer", "minimum": 1, "maximum": 1800},
                    }, "required": ["schema_version", "operation_id", "target_ids", "environment", "preconditions", "desired_state", "rollback", "max_runtime_seconds"], "additionalProperties": False},
                }, "required": ["goal_id", "operation_id", "target_ids", "environment", "plan"], "additionalProperties": False},
            },
            {
                "name": "evaluate_infrastructure_task",
                "description": "Evaluate one pending typed task against verified signed policy and code-owned risk. Optional impact_assessment must be Ed25519-signed by a trusted estimator and bind to this exact task/plan. Records classification only; it never grants execution.",
                "inputSchema": {"type": "object", "properties": {
                    "task_id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "impact_assessment": {"type": "object"},
                }, "required": ["task_id"], "additionalProperties": False},
            },
            {
                "name": "queue_approved_infrastructure_task",
                "description": "Verify a separately signed Ed25519 approval bound to the exact non-production task and queue it once. Queueing does not execute the task; no worker is connected.",
                "inputSchema": {"type": "object", "properties": {
                    "task_id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "signed_approval": {"type": "object"},
                }, "required": ["task_id", "signed_approval"], "additionalProperties": False},
            },
            {
                "name": "queue_policy_authorized_infrastructure_task",
                "description": "Revalidate the configured signed autonomy profile and exact task-bound signed impact assessment, then queue only a bounded auto-eligible non-production task under standing policy. This does not claim a worker lease or execute the task.",
                "inputSchema": {"type": "object", "properties": {
                    "task_id": {"type": "string", "minLength": 1, "maxLength": 64},
                }, "required": ["task_id"], "additionalProperties": False},
            },
            {
                "name": "get_infrastructure_goal_status",
                "description": "Read a tenant-scoped goal status, typed tasks, and tamper-evident event-chain verification. No infrastructure access.",
                "inputSchema": {"type": "object", "properties": {"goal_id": {"type": "string", "minLength": 1, "maxLength": 64}}, "required": ["goal_id"], "additionalProperties": False},
            },
        ]}}
    if method != "tools/call":
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}
    if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "invalid tool call"}}
    args = params.get("arguments", {})
    try:
        if params["name"] == "submit_infrastructure_goal":
            if set(args) != {"objective", "idempotency_key"}:
                raise ValueError("objective and idempotency_key are the only accepted arguments")
            receipt = store.submit_goal(
                tenant_id=tenant_id, requested_by=requested_by,
                idempotency_key=args["idempotency_key"], objective=args["objective"],
                guardrails=baseline_guardrails,
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": _result({**receipt.as_dict(), "execution_permitted": False})}
        if params["name"] == "get_infrastructure_goal_status":
            if set(args) != {"goal_id"}:
                raise ValueError("goal_id is the only accepted argument")
            return {"jsonrpc": "2.0", "id": request_id, "result": _result(store.get_goal_status(goal_id=args["goal_id"], tenant_id=tenant_id))}
        if params["name"] == "propose_infrastructure_task":
            if set(args) != {"goal_id", "operation_id", "target_ids", "environment", "plan"}:
                raise ValueError("goal_id, operation_id, target_ids, environment, and full plan artifact are required")
            if not isinstance(args["operation_id"], str) or not isinstance(args["environment"], str):
                raise ValueError("operation_id and environment must be strings")
            targets = args["target_ids"]
            if (not isinstance(targets, list) or not targets or len(targets) > 20
                    or any(not isinstance(target, str) or not target.strip() for target in targets)
                    or len(set(targets)) != len(targets)):
                raise ValueError("target_ids must be a list of 1-20 unique exact target IDs")
            if args["environment"] not in baseline_guardrails["allowed_environments"]:
                raise PermissionError("environment is outside the configured goal baseline")
            if not set(targets).issubset(set(baseline_guardrails["allowed_targets"])):
                raise PermissionError("one or more task targets are outside the configured exact target allowlist")
            if not isinstance(args["plan"], dict):
                raise ValueError("plan must be an object")
            task = store.add_task(
                goal_id=args["goal_id"], tenant_id=tenant_id, operation_id=args["operation_id"],
                target_ids=tuple(targets), environment=args["environment"],
                plan=args["plan"],
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": _result(task)}
        if params["name"] == "evaluate_infrastructure_task":
            if set(args) not in ({"task_id"}, {"task_id", "impact_assessment"}):
                raise ValueError("task_id and an optional signed impact_assessment are the only accepted arguments")
            task = store.claim_policy_task(task_id=args["task_id"], tenant_id=tenant_id, worker_id="codex-mcp-policy-evaluator", lease_seconds=60)
            assessment_record = None
            if autonomy_profile is None:
                disposition, reason_codes, policy_digest = "denied", ("no_verified_signed_autonomy_profile",), ""
                assessment_digest = ""
            else:
                contract = TRUSTED_OPERATION_CONTRACTS.get(task["operation_id"])
                assessment = None
                if "impact_assessment" in args:
                    try:
                        if impact_verifier is None:
                            raise PermissionError("trusted impact-assessment verification is not configured")
                        assessment = impact_verifier.verify(
                            args["impact_assessment"], expected={
                                "tenant_id": tenant_id, "task_id": task["task_id"],
                                "operation_id": task["operation_id"], "target_ids": tuple(task["target_ids"]),
                                "environment": task["environment"], "plan_digest": task["plan_digest"],
                            },
                        )
                        assessment_record = args["impact_assessment"]
                    except (ValueError, PermissionError, OSError, TimeoutError):
                        recorded = store.record_decision(
                            task_id=task["task_id"], tenant_id=tenant_id, lease_token=task["lease_token"],
                            disposition="denied", reasons=("impact_assessment_invalid_or_untrusted",), policy_digest="",
                        )
                        return {"jsonrpc": "2.0", "id": request_id, "result": _result(recorded)}
                decision = AutonomyPolicyEngine().evaluate(
                    autonomy_profile,
                    AutonomyRequest(
                        tenant_id=tenant_id, action_id=task["operation_id"],
                        target_ids=tuple(task["target_ids"]), environment=task["environment"],
                        plan_digest=task["plan_digest"], task_id=task["task_id"],
                        max_runtime_seconds=task["plan"]["max_runtime_seconds"],
                        impact_assessment=assessment,
                    ),
                    contract,
                )
                plan_reasons = validate_operation_plan(task["operation_id"], task["plan"])
                if plan_reasons:
                    disposition, reason_codes, policy_digest = "denied", plan_reasons, decision.policy_digest
                else:
                    disposition, reason_codes, policy_digest = decision.disposition.value, decision.reason_codes, decision.policy_digest
                assessment_digest = decision.impact_assessment_digest
            recorded = store.record_decision(
                task_id=task["task_id"], tenant_id=tenant_id, lease_token=task["lease_token"],
                disposition=disposition, reasons=tuple(reason_codes), policy_digest=policy_digest,
                impact_assessment_digest=assessment_digest,
                impact_assessment_record=assessment_record,
                autonomy_profile_record=(
                    autonomy_profile.signed_record
                    if disposition == "auto_eligible" and autonomy_profile is not None else None
                ),
                autonomy_profile_verifier=autonomy_profile_verifier,
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": _result(recorded)}
        if params["name"] == "queue_approved_infrastructure_task":
            if set(args) != {"task_id", "signed_approval"} or not isinstance(args["signed_approval"], dict):
                raise ValueError("task_id and a signed_approval object are required")
            queued = store.queue_task(
                task_id=args["task_id"], tenant_id=tenant_id,
                signed_approval=args["signed_approval"], approval_verifier=approval_verifier,
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": _result(queued)}
        if params["name"] == "queue_policy_authorized_infrastructure_task":
            if set(args) != {"task_id"} or not isinstance(args["task_id"], str):
                raise ValueError("task_id is the only accepted argument")
            if autonomy_profile_verifier is None or impact_verifier is None or autonomy_profile is None:
                raise PermissionError("verified standing autonomy and impact-assessment policy are not configured")
            queued = store.queue_autonomous_task(
                task_id=args["task_id"], tenant_id=tenant_id,
                autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier,
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": _result(queued)}
        raise ValueError("unknown tool")
    except (ValueError, PermissionError, KeyError, OSError) as exc:
        return {"jsonrpc": "2.0", "id": request_id, "result": {**_result({"error": str(exc)}), "isError": True}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="owner-only goal journal MCP config")
    args = parser.parse_args()
    try:
        store, tenant_id, requested_by, baseline_guardrails, autonomy_profile, impact_verifier, profile_verifier = load_settings(args.config)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"A2Z goal MCP startup failed: {exc}", file=sys.stderr)
        return 2
    try:
        for line in sys.stdin:
            try:
                message = json.loads(
                    line, object_pairs_hook=_unique_object,
                    parse_constant=_reject_json_constant,
                )
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    response = {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                                "error": {"code": -32600, "message": "invalid request"}}
                else:
                    response = dispatch(message, store=store, tenant_id=tenant_id,
                                        requested_by=requested_by, baseline_guardrails=baseline_guardrails,
                                        autonomy_profile=autonomy_profile,
                                        approval_verifier=Ed25519ApprovalVerifier(),
                                        impact_verifier=impact_verifier,
                                        autonomy_profile_verifier=profile_verifier)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            except Exception:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "internal MCP error"}}
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
