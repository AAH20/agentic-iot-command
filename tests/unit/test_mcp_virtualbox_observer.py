from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.evidence import EvidenceLedger
from control_plane_core.inventory import InventoryObservation
from scripts.mcp_virtualbox_observer import dispatch, load_settings


class VirtualBoxObserverSettingsTests(unittest.TestCase):
    def test_owner_only_registry_loads_a_single_lab_target(self):
        with tempfile.TemporaryDirectory(prefix="a2z-observer-config-") as directory:
            root = Path(directory)
            identity = root / "observer-key"
            known_hosts = root / "known_hosts"
            config_path = root / "ssh-hosts.json"
            identity.write_text("private-key-placeholder")
            known_hosts.write_text("ubuntu-vbox-lab ssh-ed25519 AAAATESTPIN\n")
            identity.chmod(0o600)
            known_hosts.chmod(0o600)
            config_path.write_text(json.dumps({
                "tenant_id": "lab",
                "hosts": [{
                    "host_id": "ubuntu-vbox-lab", "alias": "10.20.0.15",
                    "login": "a2z-observe", "environments": ["lab"],
                    "identity_file": str(identity), "known_hosts_file": str(known_hosts),
                }],
            }))
            config_path.chmod(0o600)
            tenant_id, connector, ledger, environments, baselines = load_settings(config_path)
            self.assertEqual(tenant_id, "lab")
            self.assertEqual(environments, {"ubuntu-vbox-lab": "lab"})
            self.assertEqual(baselines, {})
            self.assertTrue(connector.manifest.read_only_by_default)
            self.assertEqual(ledger.verify(tenant_id="lab")["records"], 0)

    def test_duplicate_registry_keys_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="a2z-observer-config-") as directory:
            config_path = Path(directory) / "ssh-hosts.json"
            config_path.write_text('{"tenant_id":"lab","tenant_id":"prod","hosts":[]}')
            config_path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "duplicate-free"):
                load_settings(config_path)


class VirtualBoxObserverMcpTests(unittest.TestCase):
    class Connector:
        VM_UUID = "00000000-0000-4000-8000-000000000001"

        def __init__(self):
            self.calls = []

        def observe(self, *, tenant_id, target, environment):
            self.calls.append((tenant_id, target, environment))
            common = dict(tenant_id=tenant_id, environment=environment,
                          source_connector="ssh-readonly", observed_at="2026-09-23T00:00:00Z",
                          read_only=True)
            return (
                InventoryObservation(observation_id=uuid4(), resource_id="virtualbox:host",
                    resource_type="virtualbox-host", attributes={"virtualbox_available": True}, **common),
                InventoryObservation(observation_id=uuid4(), resource_id=f"virtualbox:{self.VM_UUID}",
                    resource_type="virtualbox-vm", attributes={"uuid": self.VM_UUID, "power_state": "running"}, **common),
            )

    def setUp(self):
        self.connector = self.Connector()
        self.ledger = EvidenceLedger()
        self.tenant_id = "lab"
        self.env_by_target = {"ubuntu-vbox-lab": "lab"}

    def _baseline_compare(self, baseline):
        return dispatch({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "compare_virtualbox_to_baseline", "arguments": {"host_id": "ubuntu-vbox-lab"}},
        }, tenant_id=self.tenant_id, connector=self.connector, ledger=self.ledger,
            env_by_target=self.env_by_target, baselines={"ubuntu-vbox-lab": baseline})

    def test_observation_records_tenant_evidence_and_reports_no_change(self):
        response = dispatch({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "observe_virtualbox_host", "arguments": {"host_id": "ubuntu-vbox-lab"}},
        }, tenant_id=self.tenant_id, connector=self.connector, ledger=self.ledger,
            env_by_target=self.env_by_target)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertFalse(payload["changed_infrastructure"])
        self.assertEqual(payload["evidence"]["sequence"], 1)
        self.assertEqual(self.connector.calls, [("lab", "ubuntu-vbox-lab", "lab")])
        self.assertEqual(self.ledger.verify(tenant_id="lab")["records"], 1)

    def test_unregistered_target_and_unknown_tool_never_reach_connector(self):
        bad_target = dispatch({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "observe_virtualbox_host", "arguments": {"host_id": "other"}},
        }, tenant_id=self.tenant_id, connector=self.connector, ledger=self.ledger,
            env_by_target=self.env_by_target)
        arbitrary_tool = dispatch({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "execute_command", "arguments": {"command": "VBoxManage startvm vm-1"}},
        }, tenant_id=self.tenant_id, connector=self.connector, ledger=self.ledger,
            env_by_target=self.env_by_target)
        self.assertTrue(bad_target["result"]["isError"])
        self.assertTrue(arbitrary_tool["result"]["isError"])
        self.assertEqual(self.connector.calls, [])

    def test_baseline_comparison_reports_exact_drift_and_never_mutates_baseline(self):
        vm_uuid = self.connector.VM_UUID
        exact = {"registered_vm_uuids": [vm_uuid], "running_vm_uuids": [vm_uuid]}
        response = self._baseline_compare(exact)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertTrue(payload["baseline_match"])
        self.assertFalse(payload["changed_infrastructure"])
        self.assertFalse(payload["baseline_changed"])
        self.assertEqual(payload["evidence"]["sequence"], 1)

        drifted = {"registered_vm_uuids": [], "running_vm_uuids": []}
        response = self._baseline_compare(drifted)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertFalse(payload["baseline_match"])
        self.assertEqual(payload["drift"]["registered_unexpected"], [vm_uuid])
        self.assertEqual(payload["drift"]["running_unexpected"], [vm_uuid])
        self.assertEqual(drifted, {"registered_vm_uuids": [], "running_vm_uuids": []})
        self.assertEqual(self.ledger.verify(tenant_id="lab")["records"], 2)


class VirtualBoxBaselineValidationTests(unittest.TestCase):
    def test_baseline_rejects_unregistered_host_and_invalid_running_subset(self):
        from scripts.mcp_virtualbox_observer import _validate_baselines

        with self.assertRaisesRegex(ValueError, "configured host IDs"):
            _validate_baselines({"other": {"registered_vm_uuids": [], "running_vm_uuids": []}}, {"lab"})
        with self.assertRaisesRegex(ValueError, "running baseline VMs"):
            _validate_baselines({"lab": {
                "registered_vm_uuids": [],
                "running_vm_uuids": ["00000000-0000-4000-8000-000000000001"],
            }}, {"lab"})


if __name__ == "__main__":
    unittest.main()
