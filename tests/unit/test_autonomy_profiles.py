from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from control_plane_core.autonomy import AutonomyDisposition, AutonomyPolicyEngine, AutonomyRequest
from control_plane_core.autonomy_profiles import Ed25519AutonomyProfileVerifier, _canonical_payload, load_signed_autonomy_profile


PACKAGE = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 integration verification")
class SignedAutonomyProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-autonomy-test-")
        self.root = Path(self.temp.name)
        self.trust = self.root / "trust"
        self.trust.mkdir(mode=0o700)
        self.private_key = self.root / "private.pem"
        self.public_key = self.trust / "operator-1.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private_key), "-pubout", "-out", str(self.public_key)], check=True, capture_output=True)
        self.public_key.chmod(0o644)

    def tearDown(self):
        self.temp.cleanup()

    def signed_profile_path(self, *, maintenance_windows=None):
        profile = json.loads((PACKAGE / "policies/autonomy-defaults.json").read_text(encoding="utf-8"))
        if maintenance_windows is not None:
            profile["maintenance_windows"] = maintenance_windows
        payload_path = self.root / "payload.json"
        payload_path.write_bytes(_canonical_payload(profile))
        signature_path = self.root / "signature.bin"
        subprocess.run([
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private_key),
            "-in", str(payload_path), "-out", str(signature_path),
        ], check=True, capture_output=True)
        envelope = {
            "profile": profile,
            "signature": {
                "algorithm": "ed25519",
                "key_id": "operator-1",
                "signature_base64": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
            },
        }
        signed_path = self.root / "signed-profile.json"
        signed_path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        signed_path.chmod(0o600)
        return signed_path, envelope

    def test_valid_signature_is_derived_by_verifier_and_disabled_profile_stays_disabled(self):
        path, envelope = self.signed_profile_path()
        self.trust.chmod(0o750)
        profile = load_signed_autonomy_profile(
            path,
            verifier=Ed25519AutonomyProfileVerifier(self.trust, require_root_owned_trust=False),
            now=datetime(2026, 9, 23, 12, tzinfo=timezone.utc),
        )

        self.assertTrue(profile.verified_signature)
        self.assertFalse(profile.enabled)
        self.assertEqual(len(profile.policy_digest), 64)
        self.assertEqual(profile.signed_record, envelope)
        result = AutonomyPolicyEngine().evaluate(
            profile,
            AutonomyRequest("lab", "virtualbox.vm.refresh_inventory", ("vbox-1",), "lab", plan_digest="a" * 64),
            None,
        )
        self.assertIs(result.disposition, AutonomyDisposition.DENY)
        self.assertIn("autonomy_profile_disabled", result.reason_codes)

    def test_modified_policy_payload_fails_signature_verification(self):
        path, envelope = self.signed_profile_path()
        envelope["profile"]["tenant_id"] = "other-tenant"
        path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        path.chmod(0o600)

        with self.assertRaises(PermissionError):
            load_signed_autonomy_profile(path, verifier=Ed25519AutonomyProfileVerifier(self.trust, require_root_owned_trust=False))

    def test_signed_maintenance_window_is_parsed_and_bounded_by_profile(self):
        window = {
            "window_id": "lab-vbox-demo",
            "action_id": "virtualbox.vm.set_demo_description",
            "target_ids": ["vm-lab-1"],
            "environments": ["lab"],
            "starts_at": "2026-09-23T12:00:00Z",
            "ends_at": "2026-09-23T13:00:00Z",
        }
        path, envelope = self.signed_profile_path(maintenance_windows=[window])
        loaded = load_signed_autonomy_profile(
            path,
            verifier=Ed25519AutonomyProfileVerifier(self.trust, require_root_owned_trust=False),
            now=datetime(2026, 9, 23, 12, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(loaded.maintenance_windows[0].window_id, "lab-vbox-demo")
        self.assertEqual(loaded.signed_record, envelope)

        oversized = dict(window, ends_at="2026-09-23T21:00:00Z")
        path, _ = self.signed_profile_path(maintenance_windows=[oversized])
        with self.assertRaisesRegex(PermissionError, "at most 8 hours"):
            load_signed_autonomy_profile(
                path,
                verifier=Ed25519AutonomyProfileVerifier(self.trust, require_root_owned_trust=False),
                now=datetime(2026, 9, 23, 12, 30, tzinfo=timezone.utc),
            )

    @unittest.skipUnless(os.name == "posix", "root ownership is a POSIX deployment requirement")
    def test_production_verifier_rejects_non_root_owned_trust_directory(self):
        if self.trust.stat().st_uid == 0:
            self.skipTest("test trust directory is already root-owned")
        path, _ = self.signed_profile_path()
        with self.assertRaisesRegex(PermissionError, "must be root-owned"):
            load_signed_autonomy_profile(
                path,
                verifier=Ed25519AutonomyProfileVerifier(self.trust),
                now=datetime(2026, 9, 23, 12, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
