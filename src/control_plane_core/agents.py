from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

Mode = Literal["observe", "plan", "mutate"]


@dataclass(frozen=True)
class AgentManifest:
    agent_id: str
    tenant_id: str
    role: str
    allowed_tools: frozenset[str]
    artifact_digests: tuple[str, ...]
    signature_verified: bool = True
    read_only_by_default: bool = True


@dataclass(frozen=True)
class ToolDefinition:
    tool_id: str
    capability: str
    read_only: bool
    network: bool = False
    credentials: bool = False
    side_effects: bool = False


@dataclass(frozen=True)
class ToolCall:
    call_id: UUID
    agent_id: str
    tenant_id: str
    tool_id: str
    target: str
    mode: Mode
    capability: str
    arguments: dict[str, Any] = field(default_factory=dict)
    approval_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ToolDecision:
    call_id: UUID
    decision: str
    reason_codes: tuple[str, ...]
    execution_permitted: bool = False


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentManifest] = {}
        self._tools: dict[str, ToolDefinition] = {}

    def register_agent(self, manifest: AgentManifest) -> None:
        if not manifest.signature_verified:
            raise ValueError("agent manifest signature is not verified")
        if not manifest.read_only_by_default:
            raise ValueError("agents must be read-only by default")
        if manifest.agent_id in self._agents:
            raise ValueError("agent already registered")
        self._agents[manifest.agent_id] = manifest

    def register_tool(self, tool: ToolDefinition) -> None:
        if tool.tool_id in self._tools:
            raise ValueError("tool already registered")
        self._tools[tool.tool_id] = tool

    def agent(self, agent_id: str) -> AgentManifest | None:
        return self._agents.get(agent_id)

    def tool(self, tool_id: str) -> ToolDefinition | None:
        return self._tools.get(tool_id)


class AgentToolGateway:
    """Authorizes tool calls; it deliberately has no tool execution hook."""

    def __init__(self, registry: AgentRegistry | None = None) -> None:
        self.registry = registry or AgentRegistry()

    def authorize(self, call: ToolCall) -> ToolDecision:
        agent = self.registry.agent(call.agent_id)
        tool = self.registry.tool(call.tool_id)
        if agent is None:
            return self._deny(call, "agent_not_registered")
        if agent.tenant_id != call.tenant_id:
            return self._deny(call, "agent_tenant_boundary_violation")
        if tool is None:
            return self._deny(call, "tool_not_registered")
        if call.tool_id not in agent.allowed_tools:
            return self._deny(call, "tool_not_allowed_for_agent")
        if call.capability != tool.capability:
            return self._deny(call, "capability_mismatch")
        if tool.network or tool.credentials:
            return self._deny(call, "network_or_credentials_disabled")
        if call.mode != "observe" or not tool.read_only or tool.side_effects:
            return self._deny(call, "mutation_requires_separate_approved_runner")
        return ToolDecision(call_id=call.call_id, decision="allow", reason_codes=("read_only_tool_allowed",), execution_permitted=False)

    @staticmethod
    def _deny(call: ToolCall, reason: str) -> ToolDecision:
        return ToolDecision(call_id=call.call_id, decision="deny", reason_codes=(reason,), execution_permitted=False)


class SupervisorRouter:
    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry

    def route(self, *, tenant_id: str, role: str) -> AgentManifest:
        for agent in self.registry._agents.values():
            if agent.tenant_id == tenant_id and agent.role == role:
                return agent
        raise KeyError("no agent is registered for tenant and role")
