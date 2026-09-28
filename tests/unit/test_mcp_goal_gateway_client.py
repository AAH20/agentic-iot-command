from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mcp_goal_journal_client import SSHGoalGatewayClient, dispatch, load_client


class SSHGoalGatewayClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-ssh-goal-client-")
        self.root = Path(self.temp.name)
        self.key = self.root / "id_ed25519"
        self.known_hosts = self.root / "known_hosts"
        self.key.write_text("test-private-key-placeholder", encoding="utf-8")
        self.known_hosts.write_text("linux-lab ssh-ed25519 AAAATESTPIN", encoding="utf-8")
        self.key.chmod(0o600)
        self.known_hosts.chmod(0o600)
        self.client = SSHGoalGatewayClient(
            alias="linux-lab", login="a2z-control", identity_file=self.key,
            known_hosts_file=self.known_hosts,
            remote_gateway="/usr/local/libexec/a2z-goal-gateway",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_calls_fixed_remote_gateway_with_pinned_ssh_and_disabled_forwarding(self):
        remote = {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}
        initialize = {"jsonrpc": "2.0", "id": "a2z-proxy-initialize", "result": {}}
        output = json.dumps(initialize) + "\n" + json.dumps(remote) + "\n"
        with patch("scripts.mcp_goal_journal_client.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            result = self.client.invoke({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "submit_infrastructure_goal", "arguments": {"objective": "observe lab", "idempotency_key": "goal-1"}}})
        self.assertEqual(result, remote)
        command = run.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ForwardAgent=no", command)
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertEqual(command[-2:], ["/usr/local/libexec/a2z-goal-gateway", "--stdio"])
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_refuses_unlisted_tools_before_opening_ssh(self):
        with patch("scripts.mcp_goal_journal_client.subprocess.run") as run:
            with self.assertRaises(PermissionError):
                self.client.invoke({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_shell", "arguments": {}}})
        run.assert_not_called()

    def test_signed_approval_queue_tool_is_allowlisted(self):
        remote = {"jsonrpc": "2.0", "id": 8, "result": {"queued": True}}
        output = json.dumps({"jsonrpc": "2.0", "id": "a2z-proxy-initialize", "result": {}}) + "\n" + json.dumps(remote) + "\n"
        with patch("scripts.mcp_goal_journal_client.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            result = self.client.invoke({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
                "name": "queue_approved_infrastructure_task",
                "arguments": {"task_id": "task-1", "signed_approval": {"approval": {}, "signature": {}}},
            }})
        self.assertEqual(result, remote)
        run.assert_called_once()

    def test_policy_authorized_queue_tool_is_allowlisted(self):
        remote = {"jsonrpc": "2.0", "id": 9, "result": {"queued": True}}
        output = json.dumps({"jsonrpc": "2.0", "id": "a2z-proxy-initialize", "result": {}}) + "\n" + json.dumps(remote) + "\n"
        with patch("scripts.mcp_goal_journal_client.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            result = self.client.invoke({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
                "name": "queue_policy_authorized_infrastructure_task",
                "arguments": {"task_id": "task-1"},
            }})
        self.assertEqual(result, remote)
        run.assert_called_once()

    def test_config_requires_owner_only_and_exact_fields(self):
        config = self.root / "client.json"
        config.write_text(json.dumps({
            "ssh_alias": "linux-lab", "ssh_login": "a2z-control",
            "identity_file": str(self.key), "known_hosts_file": str(self.known_hosts),
            "remote_gateway": "/usr/local/libexec/a2z-goal-gateway",
        }), encoding="utf-8")
        config.chmod(0o600)
        self.assertIsInstance(load_client(config), SSHGoalGatewayClient)
        config.chmod(0o644)
        with self.assertRaises(PermissionError):
            load_client(config)


if __name__ == "__main__":
    unittest.main()
