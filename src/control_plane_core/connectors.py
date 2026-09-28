from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .inventory import InventoryObservation


@dataclass(frozen=True)
class ConnectorManifest:
    connector_id: str
    domain: str
    version: str
    capabilities: tuple[str, ...]
    network_destinations: tuple[str, ...] = ()
    credential_requirements: tuple[str, ...] = ()
    read_only_by_default: bool = True


class ReadOnlyConnector(Protocol):
    manifest: ConnectorManifest

    def observe(self, *, tenant_id: str, target: str, environment: str) -> tuple[InventoryObservation, ...]: ...


class ConnectorRegistry:
    """Registry for declared adapters; registration never grants credentials."""

    def __init__(self) -> None:
        self._connectors: dict[str, ReadOnlyConnector] = {}

    def register(self, connector: ReadOnlyConnector) -> None:
        manifest = connector.manifest
        if not manifest.read_only_by_default:
            raise ValueError("connector must be read-only by default")
        if manifest.connector_id in self._connectors:
            raise ValueError("connector already registered")
        self._connectors[manifest.connector_id] = connector

    def observe(self, connector_id: str, *, tenant_id: str, target: str, environment: str) -> tuple[InventoryObservation, ...]:
        connector = self._connectors.get(connector_id)
        if connector is None:
            raise KeyError("connector not registered")
        observations = connector.observe(tenant_id=tenant_id, target=target, environment=environment)
        if any(not observation.read_only for observation in observations):
            raise ValueError("connector returned a non-read-only observation")
        if any(observation.tenant_id != tenant_id for observation in observations):
            raise ValueError("connector crossed tenant boundary")
        return observations

    def manifests(self) -> tuple[ConnectorManifest, ...]:
        return tuple(connector.manifest for connector in self._connectors.values())
