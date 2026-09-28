from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from control_plane_core.ssh_connector import SSHHost, SSHReadOnlyConnector, _run_bounded_process


class SSHReadOnlyConnectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-ssh-connector-")
        root = Path(self.temp.name)
        self.identity = root / "observer-key"
        self.known_hosts = root / "known_hosts"
        self.identity.write_text("operator-private-key-placeholder")
        self.known_hosts.write_text("ubuntu-vbox-lab ssh-ed25519 AAAATESTPIN\n")
        self.identity.chmod(0o600)
        self.known_hosts.chmod(0o600)
        self.host = SSHHost(
            host_id="ubuntu-vbox-lab", alias="10.20.0.15", login="a2z-observe",
            tenant_id="lab", environments=("lab",), identity_file=self.identity,
            known_hosts_file=self.known_hosts,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_observation_uses_registered_target_and_fixed_pinned_ssh_argv(self):
        response = json.dumps({"version": 1, "observations": [{
            "operation": "virtualbox.inventory", "resource_type": "virtualbox-vm",
            "resource_id": "virtualbox:00000000-0000-0000-0000-000000000001",
            "attributes": {"name": "lab-guest", "uuid": "00000000-0000-0000-0000-000000000001", "power_state": "running"},
        }]}).encode()
        connector = SSHReadOnlyConnector((self.host,))
        with patch("control_plane_core.ssh_connector._run_bounded_process", return_value=(0, response)) as run:
            observations = connector.observe(tenant_id="lab", target="ubuntu-vbox-lab", environment="lab")
        args, request = run.call_args.args[:2]
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ForwardAgent=no", args)
        self.assertIn("ClearAllForwardings=yes", args)
        self.assertIn("/usr/local/libexec/a2z-readonly-probe", args)
        self.assertEqual(json.loads(request)["operations"], ["host.summary", "systemd.health", "virtualbox.inventory"])
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0].read_only)
        self.assertEqual(observations[0].tenant_id, "lab")

    def test_helper_cannot_inject_unapproved_or_untyped_attributes_into_evidence(self):
        cases = [
            {"name": "lab-guest", "uuid": "00000000-0000-0000-0000-000000000001",
             "power_state": "running", "environment": {"SECRET": "leak"}},
            {"name": "lab-guest", "uuid": "not-a-uuid", "power_state": "running"},
        ]
        connector = SSHReadOnlyConnector((self.host,))
        for attributes in cases:
            response = json.dumps({"version": 1, "observations": [{
                "operation": "virtualbox.inventory", "resource_type": "virtualbox-vm",
                "resource_id": "virtualbox:00000000-0000-0000-0000-000000000001",
                "attributes": attributes,
            }]}).encode()
            with self.subTest(attributes=attributes), patch(
                "control_plane_core.ssh_connector._run_bounded_process", return_value=(0, response)
            ):
                with self.assertRaises(ValueError):
                    connector.observe(tenant_id="lab", target="ubuntu-vbox-lab", environment="lab")

    def test_unknown_target_and_cross_tenant_are_denied_before_ssh(self):
        connector = SSHReadOnlyConnector((self.host,))
        with patch("control_plane_core.ssh_connector._run_bounded_process") as run:
            with self.assertRaises(PermissionError):
                connector.observe(tenant_id="other", target="ubuntu-vbox-lab", environment="lab")
            with self.assertRaises(PermissionError):
                connector.observe(tenant_id="lab", target="unregistered", environment="lab")
        run.assert_not_called()

    def test_insecure_identity_and_writable_host_key_file_are_rejected(self):
        self.identity.chmod(0o644)
        with self.assertRaisesRegex(PermissionError, "group or other"):
            SSHReadOnlyConnector((self.host,))
        self.identity.chmod(0o600)
        self.known_hosts.chmod(0o666)
        with self.assertRaisesRegex(PermissionError, "group/other writable"):
            SSHReadOnlyConnector((self.host,))

    def test_environment_must_be_an_explicit_nonproduction_label(self):
        unscoped = SSHHost(
            host_id="ubuntu-vbox-lab", alias="10.20.0.15", login="a2z-observe",
            tenant_id="lab", environments=("production",), identity_file=self.identity,
            known_hosts_file=self.known_hosts,
        )
        with self.assertRaisesRegex(ValueError, "lab, development, or staging"):
            SSHReadOnlyConnector((unscoped,))


class BoundedProcessTests(unittest.TestCase):
    def test_successful_io_and_stdout_overflow(self):
        env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
        command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"]
        status, output = _run_bounded_process(command, b"hello", timeout_seconds=3,
                                              stdout_limit=32, stderr_limit=64, environment=env)
        self.assertEqual(status, 0)
        self.assertEqual(output, b"hello")
        noisy = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*1000000)"]
        with self.assertRaisesRegex(ValueError, "response exceeds"):
            _run_bounded_process(noisy, b"", timeout_seconds=3, stdout_limit=128,
                                 stderr_limit=64, environment=env)

    def test_stderr_overflow_and_timeout_terminate_child(self):
        env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
        noisy = [sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'x'*1000000)"]
        with self.assertRaisesRegex(ValueError, "diagnostics exceed"):
            _run_bounded_process(noisy, b"", timeout_seconds=3, stdout_limit=128,
                                 stderr_limit=128, environment=env)
        slow = [sys.executable, "-c", "import time; time.sleep(5)"]
        with self.assertRaises(TimeoutError):
            _run_bounded_process(slow, b"", timeout_seconds=1, stdout_limit=128,
                                 stderr_limit=128, environment=env)


if __name__ == "__main__":
    unittest.main()
