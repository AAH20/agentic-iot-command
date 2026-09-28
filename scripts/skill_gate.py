#!/usr/bin/env python3
"""Policy evaluation and signed-review validation for quarantined skills."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ALLOW = 0
CONDITIONAL = 10
BLOCK = 22


def load_json(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _severity(value: Any) -> str:
    return str(value or "").strip().upper()


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _reference_only_incompleteness(report: dict[str, Any], policy: dict[str, Any]) -> bool:
    analysis = report.get("analysis_completeness")
    if not isinstance(analysis, dict) or analysis.get("is_complete") is True:
        return False
    if report.get("execution_successful") is not True or analysis.get("execution_successful") is not True:
        return False
    total = analysis.get("total_components")
    scanned = analysis.get("scanned_components")
    coverage = analysis.get("coverage_percent")
    if not isinstance(total, int) or total < 1 or scanned != total or coverage != 100.0:
        return False
    exceptions = analysis.get("ledger_exceptions")
    allowed_reasons = set(policy.get("reviewable_incomplete_reasons", []))
    allowed_paths = set(policy.get("reviewable_reference_paths", []))
    if not isinstance(exceptions, list) or not exceptions or not allowed_reasons or not allowed_paths:
        return False
    statuses = analysis.get("analyzer_statuses")
    if not isinstance(statuses, list) or any(
        not isinstance(item, dict) or item.get("status") not in {"completed", "not_applicable"}
        for item in statuses
    ):
        return False
    for item in exceptions:
        if not isinstance(item, dict):
            return False
        if (
            item.get("phase") != "reference_resolution"
            or item.get("reason_code") not in allowed_reasons
            or item.get("fatal") is not False
            or item.get("path") not in allowed_paths
            or not isinstance(item.get("start_line"), int)
            or item["start_line"] < 1
        ):
            return False
    return True


def reference_exception_digest(report: dict[str, Any]) -> str | None:
    analysis = report.get("analysis_completeness")
    exceptions = analysis.get("ledger_exceptions") if isinstance(analysis, dict) else None
    if not isinstance(exceptions, list) or not exceptions:
        return None
    canonical = json.dumps(exceptions, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def evaluate(report: dict[str, Any], policy: dict[str, Any]) -> tuple[str, str]:
    required = ("risk_assessment", "analysis_completeness", "execution_successful", "issues", "metadata")
    if any(key not in report for key in required):
        return "BLOCK", "report is missing required SkillSpector fields"

    risk = report["risk_assessment"]
    analysis = report["analysis_completeness"]
    issues = report["issues"]
    metadata = report["metadata"]
    if (
        not isinstance(risk, dict)
        or not isinstance(analysis, dict)
        or not isinstance(issues, list)
        or not isinstance(metadata, dict)
    ):
        return "BLOCK", "report fields have invalid types"
    if report.get("execution_successful") is not True:
        return "BLOCK", "SkillSpector execution was unsuccessful"
    if policy.get("scanner", {}).get("allow_static_only") is False and (
        metadata.get("llm_requested") is not True or metadata.get("llm_available") is not True
    ):
        return "BLOCK", "policy requires completed semantic analysis"

    score = risk.get("score")
    maximum = policy.get("thresholds", {}).get("max_risk_score")
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not isinstance(maximum, (int, float)):
        return "BLOCK", "risk score is missing or invalid"
    if score > maximum:
        return "BLOCK", "risk score exceeds the configured maximum"

    block_severities = {_severity(x) for x in policy.get("thresholds", {}).get("block_severities", [])}
    conditional_severities = {
        _severity(x) for x in policy.get("thresholds", {}).get("conditional_severities", [])
    }
    blocked_categories = {
        re.sub(r"[^a-z0-9]+", "_", str(x).strip().lower()).strip("_")
        for x in policy.get("block_categories", [])
    }

    conditional_reasons: list[str] = []
    for issue in issues:
        if not isinstance(issue, dict):
            return "BLOCK", "report contains a malformed issue"
        severity = _severity(issue.get("severity"))
        if severity in block_severities:
            return "BLOCK", f"blocked issue severity: {severity}"
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"}:
            return "BLOCK", f"unknown issue severity: {severity or '(empty)'}"
        if severity in conditional_severities:
            conditional_reasons.append(f"conditional finding {issue.get('finding_id') or issue.get('id')}")
            if not isinstance(issue.get("finding_id"), str) or not issue["finding_id"].strip():
                return "BLOCK", "conditional finding lacks a stable finding_id"

        structured_categories = _as_strings(issue.get("category")) + _as_strings(issue.get("tags"))
        for category in structured_categories:
            normalized = re.sub(r"[^a-z0-9]+", "_", category.strip().lower()).strip("_")
            if normalized in blocked_categories:
                return "BLOCK", f"finding belongs to blocked category: {normalized}"

    assessment_severity = _severity(risk.get("severity"))
    max_issue_severity = _severity(risk.get("max_issue_severity"))
    known_aggregate_severities = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if assessment_severity not in known_aggregate_severities or max_issue_severity not in known_aggregate_severities:
        return "BLOCK", "report contains an unknown aggregate severity"
    if assessment_severity in block_severities or max_issue_severity in block_severities:
        return "BLOCK", f"blocked report severity: {assessment_severity}"
    if (assessment_severity in conditional_severities or max_issue_severity in conditional_severities) and not any(
        _severity(issue.get("severity")) in conditional_severities
        for issue in issues
        if isinstance(issue, dict)
    ):
        return "BLOCK", "aggregate conditional severity has no corresponding reviewable issue"

    incomplete = analysis.get("is_complete") is not True
    if incomplete:
        if not _reference_only_incompleteness(report, policy):
            return "BLOCK", "analysis is incomplete for a reason not eligible for signed reference review"
        conditional_reasons.append("unresolved reference exceptions require exact signed review")

    recommendation = str(risk.get("recommendation") or "").strip().upper()
    safe_recommendations = {
        str(x).strip().upper() for x in policy.get("thresholds", {}).get("safe_recommendations", ["SAFE", "ALLOW"])
    }
    conditional_recommendations = {
        str(x).strip().upper()
        for x in policy.get("thresholds", {}).get("conditional_recommendations", ["CAUTION"])
    }
    if recommendation in conditional_recommendations:
        conditional_reasons.append(f"scanner recommendation {recommendation} requires signed review")
    elif recommendation not in safe_recommendations:
        return "BLOCK", f"scanner recommendation is not eligible: {recommendation or '(empty)'}"

    if conditional_reasons:
        return "CONDITIONAL", "; ".join(dict.fromkeys(conditional_reasons))
    return "ALLOW", "report satisfies the automatic scan policy"


def _parse_time(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"approval {field} must be an ISO-8601 string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"approval {field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_approval(
    report: dict[str, Any],
    policy: dict[str, Any],
    envelope: dict[str, Any],
    artifact_digest: str,
    report_digest: str,
) -> None:
    decision, reason = evaluate(report, policy)
    if decision == "BLOCK":
        raise ValueError(reason)
    approval = envelope.get("approval")
    signature = envelope.get("signature")
    if not isinstance(approval, dict) or not isinstance(signature, dict):
        raise ValueError("approval envelope must contain approval and signature objects")
    if set(envelope) != {"approval", "signature"}:
        raise ValueError("approval envelope has unexpected top-level fields")
    required = {"artifact_id", "report_sha256", "owner", "approved_at", "expires_at", "safe_to_install"}
    if not required.issubset(approval):
        raise ValueError(f"approval is missing required fields: {sorted(required - set(approval))}")
    allowed_fields = required | {"review"}
    if set(approval) - allowed_fields:
        raise ValueError("approval contains unexpected fields")
    if approval["artifact_id"] != f"sha256:{artifact_digest}" or approval["report_sha256"] != report_digest:
        raise ValueError("approval does not bind the exact scanned artifact and report")
    if approval["safe_to_install"] is not True or not isinstance(approval["owner"], str) or not approval["owner"].strip():
        raise ValueError("approval must explicitly authorize installation and name an owner")

    now = dt.datetime.now(dt.timezone.utc)
    approved_at = _parse_time(approval["approved_at"], "approved_at")
    expires_at = _parse_time(approval["expires_at"], "expires_at")
    if approved_at > now or expires_at <= now or expires_at <= approved_at:
        raise ValueError("approval timestamps are invalid, future-dated, or expired")
    max_days = int(policy.get("approval", {}).get("max_approval_days", 30))
    if expires_at > approved_at + dt.timedelta(days=max_days):
        raise ValueError("approval lifetime exceeds the policy maximum")

    if signature.get("algorithm") != "ed25519" or not signature.get("key_id") or not signature.get("signature_base64"):
        raise ValueError("approval signature metadata is invalid")

    review = approval.get("review")
    if decision == "ALLOW":
        if review is not None:
            raise ValueError("review details may only be attached to a conditional scan decision")
        return
    if not isinstance(review, dict) or set(review) != {"notes", "findings", "reference_exceptions_sha256"}:
        raise ValueError("conditional decision requires signed review notes, findings, and reference digest")
    notes = review.get("notes")
    minimum_notes = int(policy.get("conditional_review", {}).get("minimum_notes_length", 20))
    minimum_mitigation = int(policy.get("conditional_review", {}).get("minimum_mitigation_length", 20))
    if not isinstance(notes, str) or len(notes.strip()) < minimum_notes:
        raise ValueError("conditional review notes must explain the review and mitigation")

    expected_findings = {
        issue["finding_id"]: _severity(issue.get("severity"))
        for issue in report["issues"]
        if isinstance(issue, dict) and _severity(issue.get("severity")) in {
            _severity(x) for x in policy.get("thresholds", {}).get("conditional_severities", [])
        }
    }
    reviewed = review.get("findings")
    if not isinstance(reviewed, list):
        raise ValueError("review.findings must be an array")
    reviewed_by_id: dict[str, dict[str, Any]] = {}
    for item in reviewed:
        if not isinstance(item, dict) or set(item) != {"finding_id", "severity", "mitigation"}:
            raise ValueError("each reviewed finding must include only finding_id, severity, and mitigation")
        finding_id = item.get("finding_id")
        mitigation = item.get("mitigation")
        if not isinstance(finding_id, str) or finding_id in reviewed_by_id:
            raise ValueError("reviewed finding IDs must be unique strings")
        if not isinstance(mitigation, str) or len(mitigation.strip()) < minimum_mitigation:
            raise ValueError(f"finding {finding_id} needs a specific mitigation")
        reviewed_by_id[finding_id] = item
    if set(reviewed_by_id) != set(expected_findings):
        raise ValueError("signed review must address every and only conditional scanner finding")
    for finding_id, severity in expected_findings.items():
        if _severity(reviewed_by_id[finding_id].get("severity")) != severity:
            raise ValueError(f"severity mismatch in review for finding {finding_id}")

    expected_exception_digest = reference_exception_digest(report)
    supplied_exception_digest = review.get("reference_exceptions_sha256")
    if expected_exception_digest is None:
        if supplied_exception_digest is not None:
            raise ValueError("review contains a reference digest but the report has no reference exceptions")
    elif supplied_exception_digest != expected_exception_digest:
        raise ValueError("review does not bind the exact unresolved-reference exception list")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("report")
    evaluate_parser.add_argument("policy")
    review_parser = sub.add_parser("review-material")
    review_parser.add_argument("report")
    review_parser.add_argument("policy")
    approval_parser = sub.add_parser("validate-approval")
    approval_parser.add_argument("report")
    approval_parser.add_argument("policy")
    approval_parser.add_argument("approval")
    approval_parser.add_argument("artifact_sha256")
    approval_parser.add_argument("report_sha256")
    args = parser.parse_args()

    try:
        report = load_json(args.report)
        policy = load_json(args.policy)
        if args.command == "evaluate":
            decision, explanation = evaluate(report, policy)
            print(f"{decision}: {explanation}")
            return {"ALLOW": ALLOW, "CONDITIONAL": CONDITIONAL, "BLOCK": BLOCK}[decision]
        if args.command == "review-material":
            findings = [
                {
                    "finding_id": issue.get("finding_id"),
                    "severity": _severity(issue.get("severity")),
                    "mitigation": "",
                }
                for issue in report.get("issues", [])
                if isinstance(issue, dict)
                and _severity(issue.get("severity")) in {
                    _severity(x)
                    for x in policy.get("thresholds", {}).get("conditional_severities", [])
                }
            ]
            print(
                json.dumps(
                    {
                        "notes": "",
                        "findings": findings,
                        "reference_exceptions_sha256": reference_exception_digest(report),
                    },
                    indent=2,
                )
            )
            return 0
        envelope = load_json(args.approval)
        validate_approval(report, policy, envelope, args.artifact_sha256, args.report_sha256)
        print("ALLOW: signed approval matches the policy and exact scan report")
        return 0
    except (OSError, json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
        print(f"BLOCK: {exc}", file=sys.stderr)
        return BLOCK


if __name__ == "__main__":
    raise SystemExit(main())
