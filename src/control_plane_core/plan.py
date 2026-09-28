from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4


ALLOWED_ACTIONS = frozenset({"create", "update", "delete", "read"})


@dataclass(frozen=True)
class PlanEvaluation:
    evaluation_id: UUID
    plan_sha256: str
    decision: str
    resource_count: int
    destructive_count: int
    reason_codes: tuple[str, ...]
    execution_permitted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "evaluation_id": str(self.evaluation_id),
            "plan_sha256": self.plan_sha256,
            "decision": self.decision,
            "resource_count": self.resource_count,
            "destructive_count": self.destructive_count,
            "reason_codes": list(self.reason_codes),
            "execution_permitted": self.execution_permitted,
        }


class OfflinePlanService:
    """Evaluates an already-produced plan artifact without invoking Terraform/OpenTofu."""

    def evaluate(self, artifact: dict[str, Any]) -> PlanEvaluation:
        if not isinstance(artifact, dict):
            raise ValueError("plan artifact must be an object")
        if not artifact.get("format_version") or not artifact.get("terraform_version"):
            raise ValueError("plan artifact version fields are required")
        changes = artifact.get("resource_changes")
        if not isinstance(changes, list):
            raise ValueError("resource_changes must be an array")
        destructive = 0
        reasons: list[str] = ["offline_artifact_only", "execution_disabled"]
        for entry in changes:
            if not isinstance(entry, dict) or not isinstance(entry.get("address"), str):
                raise ValueError("each resource change requires an address")
            change = entry.get("change")
            actions = change.get("actions") if isinstance(change, dict) else None
            if not isinstance(actions, list) or not actions or any(action not in ALLOWED_ACTIONS for action in actions):
                raise ValueError("resource actions are invalid")
            if "delete" in actions:
                destructive += 1
        if destructive:
            reasons.append("destructive_change_requires_human_review")
        return PlanEvaluation(
            evaluation_id=uuid4(),
            plan_sha256=hashlib.sha256(json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            decision="conditional" if destructive else "allow",
            resource_count=len(changes),
            destructive_count=destructive,
            reason_codes=tuple(reasons),
            execution_permitted=False,
        )
