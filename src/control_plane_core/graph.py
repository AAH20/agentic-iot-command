from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from uuid import UUID, uuid4


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    tenant_id: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphEdge:
    edge_id: UUID
    tenant_id: str
    source_id: str
    target_id: str
    relation: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["edge_id"] = str(self.edge_id)
        return result


@dataclass(frozen=True)
class GraphQueryResult:
    tenant_id: str
    root_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    depth: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "root_id": self.root_id,
            "nodes": [node.as_dict() for node in self.nodes],
            "edges": [edge.as_dict() for edge in self.edges],
            "depth": self.depth,
            "execution_permitted": False,
        }


class RelationshipGraph:
    """In-memory, tenant-scoped relationship graph for local reference use.

    This is the graph-query boundary from the architecture. It stores only
    caller-supplied evidence and never discovers, mutates, or connects to a
    provider. Tenant checks happen at both write and query boundaries.
    """

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], GraphNode] = {}
        self._edges: dict[tuple[str, UUID], GraphEdge] = {}

    def add_node(self, node: GraphNode) -> GraphNode:
        self._require_scope(node.tenant_id, node.node_id)
        if not node.kind.strip():
            raise ValueError("graph node kind must be non-empty")
        if not isinstance(node.attributes, dict):
            raise ValueError("graph node attributes must be an object")
        self._nodes[(node.tenant_id, node.node_id)] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self._require_scope(edge.tenant_id, edge.source_id)
        self._require_scope(edge.tenant_id, edge.target_id)
        if edge.source_id == edge.target_id:
            raise ValueError("self-referential graph edges are not accepted")
        for endpoint_id in (edge.source_id, edge.target_id):
            if (edge.tenant_id, endpoint_id) not in self._nodes:
                if any(node.node_id == endpoint_id for node in self._nodes.values()):
                    raise PermissionError("graph edge crosses tenant boundary")
                raise KeyError("graph edge endpoints must exist in the same tenant")
        if not edge.relation.strip():
            raise ValueError("graph edge relation must be non-empty")
        if not isinstance(edge.attributes, dict):
            raise ValueError("graph edge attributes must be an object")
        self._edges[(edge.tenant_id, edge.edge_id)] = edge
        return edge

    def list_for_tenant(self, tenant_id: str) -> dict[str, list[dict[str, Any]]]:
        if not tenant_id.strip():
            raise ValueError("tenant_id is required")
        return {
            "nodes": [node.as_dict() for (scope, _), node in self._nodes.items() if scope == tenant_id],
            "edges": [edge.as_dict() for (scope, _), edge in self._edges.items() if scope == tenant_id],
        }

    def query(self, *, tenant_id: str, root_id: str, depth: int = 1, direction: Literal["both", "out", "in"] = "both") -> GraphQueryResult:
        self._require_scope(tenant_id, root_id)
        if depth < 0 or depth > 3:
            raise ValueError("graph query depth must be between 0 and 3")
        if direction not in {"both", "out", "in"}:
            raise ValueError("graph query direction is invalid")
        if (tenant_id, root_id) not in self._nodes:
            if any(node.node_id == root_id for node in self._nodes.values()):
                raise PermissionError("graph query crosses tenant boundary")
            raise KeyError("graph root does not exist in tenant")

        seen = {root_id}
        frontier = deque([(root_id, 0)])
        selected_edges: dict[tuple[str, UUID], GraphEdge] = {}
        while frontier:
            current, current_depth = frontier.popleft()
            if current_depth >= depth:
                continue
            for edge in sorted(self._edges.values(), key=lambda item: str(item.edge_id)):
                if edge.tenant_id != tenant_id:
                    continue
                next_id: str | None = None
                if direction in {"both", "out"} and edge.source_id == current:
                    next_id = edge.target_id
                elif direction in {"both", "in"} and edge.target_id == current:
                    next_id = edge.source_id
                if next_id is None:
                    continue
                selected_edges[(edge.tenant_id, edge.edge_id)] = edge
                if next_id not in seen:
                    seen.add(next_id)
                    frontier.append((next_id, current_depth + 1))

        nodes = tuple(self._nodes[(tenant_id, node_id)] for node_id in sorted(seen))
        edges = tuple(selected_edges[edge_key] for edge_key in sorted(selected_edges, key=lambda item: str(item[1])))
        return GraphQueryResult(tenant_id=tenant_id, root_id=root_id, nodes=nodes, edges=edges, depth=depth)

    @staticmethod
    def _require_scope(tenant_id: str, resource_id: str) -> None:
        if not tenant_id.strip() or not resource_id.strip():
            raise ValueError("tenant and graph identifiers are required")
