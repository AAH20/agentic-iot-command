from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from control_plane_core.worker_api_registry import load_runner_certificate_registry
from control_plane_core.worker_api_service import (
    _check_database_path,
    _validate_disabled_execution_control,
    _validate_trust_directory,
    load_worker_api_config,
)


class WorkerAPIServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-worker-api-service-")
        self.root = Path(self.temp.name).resolve()
        self.config = json.loads((Path(__file__).resolve().parents[2] / "config/worker-api.example.json").read_text())
        self.config["signer_uid"] = os.geteuid() + 1
        self.path = self.root / "worker-api.json"
        self.path.write_text(json.dumps(self.config), encoding="utf-8")
        self.path.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_worker_api_config_is_exact_loopback_and_fixed_port(self):
        with patch("control_plane_core.worker_api_service._check_database_path",
                   return_value=Path(self.config["database_path"])):
            loaded = load_worker_api_config(self.path, require_root_owned=False)
        self.assertEqual(loaded["bind_address"], "127.0.0.1")
        for field, value in (("bind_address", "0.0.0.0"), ("bind_address", "::1"), ("port", 9444),
                             ("signer_uid", os.geteuid()),
                             ("tls_certificate", str(self.root / "rogue.crt"))):
            self.path.write_text(json.dumps(dict(self.config, **{field: value})), encoding="utf-8")
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, PermissionError)):
                load_worker_api_config(self.path, require_root_owned=False)

    def test_execution_switch_config_check_requires_disabled_root_managed_record(self):
        switch = self.root / "execution-control.json"
        switch.write_text(json.dumps({
            "schema_version": "a2z-execution-control-v1", "execution_enabled": False,
            "issued_at": "2026-09-01T00:00:00Z", "expires_at": "2026-09-01T00:10:00Z",
            "reason": "staged test",
        }), encoding="utf-8")
        switch.chmod(0o600)
        _validate_disabled_execution_control(str(switch), require_root_owned=False)
        enabled = json.loads(switch.read_text())
        enabled["execution_enabled"] = True
        switch.write_text(json.dumps(enabled), encoding="utf-8")
        with self.assertRaisesRegex(PermissionError, "switch to be disabled"):
            _validate_disabled_execution_control(str(switch), require_root_owned=False)

    def test_trust_directory_rejects_private_keys_and_unbounded_files(self):
        trust = self.root / "trust"
        trust.mkdir(mode=0o700)
        public_key = trust / "issuer.pem"
        public_key.write_bytes(b"-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")
        public_key.chmod(0o600)
        _validate_trust_directory(str(trust), require_root_owned=False)
        public_key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
        with self.assertRaisesRegex(PermissionError, "public-key PEM"):
            _validate_trust_directory(str(trust), require_root_owned=False)

    def test_database_must_live_in_private_service_owned_directory(self):
        _check_database_path(self.root / "db.sqlite3", require_service_owner=True)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(PermissionError, "owner-only"):
            _check_database_path(self.root / "db.sqlite3", require_service_owner=True)

    def test_runner_identity_registry_pins_unique_runner_certificate_scope(self):
        registry_path = self.root / "runner-identities.json"
        record = {
            "spiffe_id": "spiffe://a2z.example/tenant/lab-tenant/runner/runner-1",
            "tenant_id": "lab-tenant", "runner_id": "runner-1", "certificate_sha256": "a" * 64,
            "target_ids": ["vm-1"], "operation_ids": ["virtualbox.vm.set_demo_description"],
            "environments": ["lab"],
        }
        document = {"schema_version": "a2z-runner-certificate-registry-v1", "identities": [record]}
        registry_path.write_text(json.dumps(document), encoding="utf-8")
        registry_path.chmod(0o600)
        registry = load_runner_certificate_registry(registry_path, require_root_owned=False)
        self.assertEqual(registry._identities[record["spiffe_id"]].runner_id, "runner-1")
        record["environments"] = ["production"]
        registry_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises((ValueError, PermissionError)):
            load_runner_certificate_registry(registry_path, require_root_owned=False)


if __name__ == "__main__":
    unittest.main()
