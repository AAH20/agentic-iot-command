from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from control_plane_core.postcondition_registry import load_postcondition_verifier_registry


def record(**overrides):
    value = {
        "spiffe_id": "spiffe://a2z.example/tenant/lab-tenant/verifier/observer-1",
        "verifier_id": "observer-1",
        "tenant_id": "lab-tenant",
        "certificate_sha256": "a" * 64,
        "target_ids": ["vm-lab-1"],
        "operation_ids": ["virtualbox.vm.set_demo_description"],
        "environments": ["lab"],
    }
    value.update(overrides)
    return value


class PostconditionRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-postcondition-registry-")
        self.path = Path(self.temp.name) / "verifiers.json"

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")
        self.path.chmod(0o640)

    def test_loads_exact_registry_and_preserves_server_owned_scope(self):
        self._write({
            "schema_version": "a2z-postcondition-verifier-registry-v1",
            "identities": [record()],
        })
        registry = load_postcondition_verifier_registry(self.path, require_root_owned=False)
        identity = registry._identities["spiffe://a2z.example/tenant/lab-tenant/verifier/observer-1"]
        self.assertEqual(identity.verifier_id, "observer-1")
        self.assertEqual(identity.target_ids, frozenset({"vm-lab-1"}))
        self.assertEqual(identity.operation_ids, frozenset({"virtualbox.vm.set_demo_description"}))

    def test_rejects_writable_files_and_symlink_paths(self):
        self._write({"schema_version": "a2z-postcondition-verifier-registry-v1", "identities": [record()]})
        self.path.chmod(0o666)
        with self.assertRaisesRegex(PermissionError, "writable"):
            load_postcondition_verifier_registry(self.path, require_root_owned=False)
        self.path.chmod(0o640)
        link = Path(self.temp.name) / "link.json"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(PermissionError, "non-symlink"):
            load_postcondition_verifier_registry(link, require_root_owned=False)

    def test_rejects_user_owned_parent_symlink(self):
        directory = Path(self.temp.name) / "real"
        directory.mkdir()
        target = directory / "verifiers.json"
        target.write_text(json.dumps({
            "schema_version": "a2z-postcondition-verifier-registry-v1",
            "identities": [record()],
        }), encoding="utf-8")
        target.chmod(0o640)
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(PermissionError, "root-owned symlinks"):
            load_postcondition_verifier_registry(alias / "verifiers.json", require_root_owned=False)

    def test_rejects_duplicate_keys_unknown_fields_and_oversized_input(self):
        self.path.write_text(
            '{"schema_version":"a2z-postcondition-verifier-registry-v1",'
            '"schema_version":"a2z-postcondition-verifier-registry-v1","identities":[]}',
            encoding="utf-8",
        )
        self.path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "strict UTF-8 JSON"):
            load_postcondition_verifier_registry(self.path, require_root_owned=False)
        self._write({
            "schema_version": "a2z-postcondition-verifier-registry-v1",
            "identities": [record(), record(extra="not-allowed")],
        })
        with self.assertRaisesRegex(ValueError, "identity fields"):
            load_postcondition_verifier_registry(self.path, require_root_owned=False)
        self.path.write_bytes(b" " * (256 * 1024 + 1))
        self.path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            load_postcondition_verifier_registry(self.path, require_root_owned=False)

    def test_rejects_production_wildcards_duplicate_identities_and_fingerprints(self):
        base = {"schema_version": "a2z-postcondition-verifier-registry-v1"}
        for bad_record, message in (
            (record(environments=["production"]), "production environments"),
            (record(target_ids=["*"]), "exact allowlist"),
            (record(target_ids=["vm-lab-1", "vm-lab-1"]), "unique non-empty"),
        ):
            self._write({**base, "identities": [bad_record]})
            with self.subTest(message=message), self.assertRaises((PermissionError, ValueError)) as raised:
                load_postcondition_verifier_registry(self.path, require_root_owned=False)
            self.assertIn(message, str(raised.exception))
        duplicate = record(spiffe_id="spiffe://a2z.example/tenant/lab-tenant/verifier/observer-2",
                           verifier_id="observer-2")
        self._write({**base, "identities": [record(), duplicate]})
        with self.assertRaisesRegex(ValueError, "fingerprints"):
            load_postcondition_verifier_registry(self.path, require_root_owned=False)

    def test_default_mode_requires_root_owned_registry(self):
        self._write({
            "schema_version": "a2z-postcondition-verifier-registry-v1",
            "identities": [record()],
        })
        if os.geteuid() == 0:
            self.skipTest("test process is root; cannot create an untrusted owner fixture")
        with self.assertRaisesRegex(PermissionError, "root-owned"):
            load_postcondition_verifier_registry(self.path)


if __name__ == "__main__":
    unittest.main()
