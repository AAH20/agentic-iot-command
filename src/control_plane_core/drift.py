from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True)
class DriftEvent:
    event_id: UUID
    tenant_id: str
    resource_id: str
    desired_hash: str
    observed_hash: str
    drifted: bool
    changed_fields: tuple[str, ...]
    severity: str
    execution_permitted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "tenant_id": self.tenant_id,
            "resource_id": self.resource_id,
            "desired_hash": self.desired_hash,
            "observed_hash": self.observed_hash,
            "drifted": self.drifted,
            "changed_fields": list(self.changed_fields),
            "severity": self.severity,
            "execution_permitted": self.execution_permitted,
        }


class DriftDetector:
    """Deterministic desired-vs-observed comparison with no mutation path."""

    def compare(self, *, tenant_id: str, resource_id: str, desired: dict[str, Any], observed: dict[str, Any]) -> DriftEvent:
        if not tenant_id.strip() or not resource_id.strip():
            raise ValueError("tenant and resource identifiers are required")
        if not isinstance(desired, dict) or not isinstance(observed, dict):
            raise ValueError("desired and observed states must be objects")
        changed = tuple(self._changed_paths(desired, observed))
        drifted = bool(changed)
        return DriftEvent(
            event_id=uuid4(),
            tenant_id=tenant_id,
            resource_id=resource_id,
            desired_hash=self._hash(desired),
            observed_hash=self._hash(observed),
            drifted=drifted,
            changed_fields=changed,
            severity="medium" if drifted else "none",
            execution_permitted=False,
        )

    @classmethod
    def _hash(cls, value: dict[str, Any]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _changed_paths(cls, desired: Any, observed: Any, prefix: str = "") -> list[str]:
        if isinstance(desired, dict) and isinstance(observed, dict):
            paths: list[str] = []
            for key in sorted(set(desired) | set(observed)):
                path = f"{prefix}.{key}" if prefix else str(key)
                if key not in desired or key not in observed:
                    paths.append(path)
                else:
                    paths.extend(cls._changed_paths(desired[key], observed[key], path))
            return paths
        if desired != observed:
            return [prefix or "$"]
        return []

