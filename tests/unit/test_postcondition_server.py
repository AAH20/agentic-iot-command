from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from control_plane_core.postcondition_server import (
    load_postcondition_api_config,
    validate_postcondition_api_configuration,
)


class PostconditionServerConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-postcondition-server-config-")
        root = Path(self.temp.name)
        self.db_dir = root / "state"
        self.db_dir.mkdir(mode=0o700)
        self.config_path = root / "postcondition-api.json"
        self.config = {
            "schema_version": "a2z-postcondition-api-config-v1",
            "database_path": str(self.db_dir / "goals.sqlite3"),
            "verifier_registry_path": str(root / "verifiers.json"),
            "verifier_trust_directory": str(root / "trust"),
            "tls_certificate": str(root / "server.crt"),
            "tls_private_key": str(root / "server.key"),
            "client_ca": str(root / "client-ca.crt"),
            "bind_address": "127.0.0.1",
            "port": 9444,
        }
        self._write()

    def tearDown(self):
        self.temp.cleanup()

    def _write(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.config_path.chmod(0o640)

    def test_accepts_owner_only_database_and_loopback_service_configuration(self):
        loaded = load_postcondition_api_config(self.config_path, require_root_owned=False)
        self.assertEqual(loaded["bind_address"], "127.0.0.1")
        self.assertEqual(loaded["port"], 9444)
        self.assertEqual(Path(loaded["database_path"]), Path(self.config["database_path"]).resolve())

    def test_rejects_non_loopback_or_non_numeric_listener_addresses(self):
        for address in ("0.0.0.0", "192.0.2.20", "localhost"):
            with self.subTest(address=address):
                self.config["bind_address"] = address
                self._write()
                with self.assertRaises((ValueError, PermissionError)):
                    load_postcondition_api_config(self.config_path, require_root_owned=False)

    def test_rejects_unsafe_database_directory_database_file_and_symlink(self):
        self.db_dir.chmod(0o755)
        with self.assertRaisesRegex(PermissionError, "not be accessible"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)
        self.db_dir.chmod(0o700)
        actual = self.db_dir / "actual.sqlite3"
        actual.touch()
        actual.chmod(0o644)
        self.config["database_path"] = str(actual)
        self._write()
        with self.assertRaisesRegex(PermissionError, "database must be owner-only"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)
        actual.chmod(0o600)
        alias = self.db_dir / "goals.sqlite3"
        alias.symlink_to(actual)
        self.config["database_path"] = str(alias)
        self._write()
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)

    def test_rejects_untrusted_config_mode_and_root_owner_requirement(self):
        self.config_path.chmod(0o666)
        with self.assertRaisesRegex(PermissionError, "permissions are too broad"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)
        self.config_path.chmod(0o640)
        if os.geteuid() == 0:
            self.skipTest("test process is root; cannot create an untrusted owner fixture")
        with self.assertRaisesRegex(PermissionError, "must be root-owned"):
            load_postcondition_api_config(self.config_path)

    def test_rejects_unknown_config_fields_and_duplicate_json_keys(self):
        self.config["extra"] = True
        self._write()
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)
        self.config_path.write_text(
            '{"schema_version":"a2z-postcondition-api-config-v1",'
            '"schema_version":"a2z-postcondition-api-config-v1"}', encoding="utf-8",
        )
        self.config_path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "strict UTF-8 JSON"):
            load_postcondition_api_config(self.config_path, require_root_owned=False)

    def test_check_mode_loads_trust_material_without_opening_database_or_listener(self):
        openssl = Path("/usr/bin/openssl")
        if not openssl.is_file():
            self.skipTest("system OpenSSL is unavailable")
        root = Path(self.temp.name)
        trust = root / "trust"
        trust.mkdir(mode=0o750)
        (trust / "observer-key.pem").write_text("public-key-fixture", encoding="ascii")
        (trust / "observer-key.pem").chmod(0o640)
        registry = root / "verifiers.json"
        registry.write_text(json.dumps({
            "schema_version": "a2z-postcondition-verifier-registry-v1",
            "identities": [{
                "spiffe_id": "spiffe://a2z.example/tenant/lab-tenant/verifier/observer-1",
                "verifier_id": "observer-1", "tenant_id": "lab-tenant",
                "certificate_sha256": "a" * 64, "target_ids": ["vm-lab-1"],
                "operation_ids": ["virtualbox.vm.set_demo_description"],
                "environments": ["lab"],
            }],
        }), encoding="utf-8")
        registry.chmod(0o640)
        key, certificate = root / "server.key", root / "server.crt"
        subprocess.run([
            str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost",
        ], check=True, capture_output=True, timeout=20)
        key.chmod(0o600)
        certificate.chmod(0o640)
        self.config.update({
            "verifier_registry_path": str(registry),
            "verifier_trust_directory": str(trust),
            "tls_certificate": str(certificate),
            "tls_private_key": str(key),
            "client_ca": str(certificate),
        })
        self._write()
        validate_postcondition_api_configuration(self.config_path, require_root_owned=False)
        self.assertFalse((self.db_dir / "goals.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
