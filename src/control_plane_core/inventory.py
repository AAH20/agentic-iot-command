from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True)
class InventoryObservation:
    observation_id: UUID
    tenant_id: str
    resource_id: str
    resource_type: str
    environment: str
    source_connector: str
    observed_at: str
    read_only: bool
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["observation_id"] = str(self.observation_id)
        return result


class SyntheticReadOnlyConnector:
    """Deterministic lab connector used for contract tests only."""

    def __init__(self, connector_id: str, resource_type: str, attributes: dict[str, Any] | None = None) -> None:
        self.connector_id = connector_id
        self.resource_type = resource_type
        self.attributes = attributes or {}

    @property
    def manifest(self):
        from .connectors import ConnectorManifest

        return ConnectorManifest(
            connector_id=self.connector_id,
            domain=self.resource_type,
            version="0.1.0",
            capabilities=("observe",),
            network_destinations=(),
            credential_requirements=(),
            read_only_by_default=True,
        )

    def observe(self, *, tenant_id: str, target: str, environment: str) -> tuple[InventoryObservation, ...]:
        return (
            InventoryObservation(
                observation_id=uuid4(),
                tenant_id=tenant_id,
                resource_id=target,
                resource_type=self.resource_type,
                environment=environment,
                source_connector=self.connector_id,
                observed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                read_only=True,
                attributes=dict(self.attributes),
            ),
        )
