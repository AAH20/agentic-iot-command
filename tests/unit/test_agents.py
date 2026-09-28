import unittest
from uuid import uuid4

from control_plane_core.agents import (
    AgentManifest,
    AgentRegistry,
    AgentToolGateway,
    SupervisorRouter,
    ToolCall,
    ToolDefinition,
)


class AgentGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AgentRegistry()
        self.registry.register_agent(
            AgentManifest(
                agent_id="inventory-agent",
                tenant_id="tenant-a",
                role="inventory",
                allowed_tools=frozenset({"asset.inventory.read"}),
                artifact_digests=("sha256:" + "a" * 64,),
            )
        )
        self.registry.register_tool(
            ToolDefinition(tool_id="asset.inventory.read", capability="inventory.read", read_only=True)
        )
        self.gateway = AgentToolGateway(self.registry)

    def test_read_only_tool_is_authorized_but_not_executed(self) -> None:
        decision = self.gateway.authorize(
            ToolCall(
                call_id=uuid4(),
                agent_id="inventory-agent",
                tenant_id="tenant-a",
                tool_id="asset.inventory.read",
                target="asset-1",
                mode="observe",
                capability="inventory.read",
            )
        )
        self.assertEqual(decision.decision, "allow")
        self.assertFalse(decision.execution_permitted)

    def test_unknown_or_mutating_tools_are_denied(self) -> None:
        unknown = self.gateway.authorize(
            ToolCall(uuid4(), "inventory-agent", "tenant-a", "shell.exec", "asset-1", "observe", "shell", {})
        )
        self.assertEqual(unknown.decision, "deny")
        mutating = self.gateway.authorize(
            ToolCall(uuid4(), "inventory-agent", "tenant-a", "asset.inventory.read", "asset-1", "mutate", "inventory.read", {})
        )
        self.assertEqual(mutating.decision, "deny")
        self.assertIn("mutation_requires_separate_approved_runner", mutating.reason_codes)

    def test_network_or_credential_tool_is_denied(self) -> None:
        self.registry.register_tool(ToolDefinition("cloud.read", "cloud.read", True, network=True))
        self.registry._agents["inventory-agent"] = AgentManifest(
            agent_id="inventory-agent",
            tenant_id="tenant-a",
            role="inventory",
            allowed_tools=frozenset({"asset.inventory.read", "cloud.read"}),
            artifact_digests=("sha256:" + "a" * 64,),
        )
        decision = self.gateway.authorize(
            ToolCall(uuid4(), "inventory-agent", "tenant-a", "cloud.read", "asset-1", "observe", "cloud.read", {})
        )
        self.assertEqual(decision.decision, "deny")
        self.assertIn("network_or_credentials_disabled", decision.reason_codes)

    def test_cross_tenant_call_and_unverified_agent_are_denied(self) -> None:
        decision = self.gateway.authorize(
            ToolCall(uuid4(), "inventory-agent", "tenant-b", "asset.inventory.read", "asset-1", "observe", "inventory.read", {})
        )
        self.assertEqual(decision.decision, "deny")
        with self.assertRaises(ValueError):
            self.registry.register_agent(
                AgentManifest("unverified", "tenant-a", "inventory", frozenset(), (), signature_verified=False)
            )

    def test_supervisor_routes_only_within_tenant(self) -> None:
        agent = SupervisorRouter(self.registry).route(tenant_id="tenant-a", role="inventory")
        self.assertEqual(agent.agent_id, "inventory-agent")
        with self.assertRaises(KeyError):
            SupervisorRouter(self.registry).route(tenant_id="tenant-b", role="inventory")


if __name__ == "__main__":
    unittest.main()
