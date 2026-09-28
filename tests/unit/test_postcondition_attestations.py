from __future__ import annotations

import datetime as dt
import base64
import subprocess
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.postcondition_attestations import (
    Ed25519PostconditionAttestationSigner,
    Ed25519PostconditionAttestationVerifier,
)


class StructuralVerifier(Ed25519PostconditionAttestationVerifier):
    def _verify_signature(self, key_id, payload, signature):
        self.signature_checked = True


class PostconditionAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-postcondition-test-")
        self.root = Path(self.temp.name)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.attestation = {
            "schema_version": "a2z-postcondition-attestation-v1",
            "verification_id": str(uuid4()), "receipt_id": str(uuid4()),
            "task_id": str(uuid4()), "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "plan_digest": "a" * 64, "lease_generation": 2,
            "verifier_id": "observer-lab-1",
            "observed_at": now.isoformat().replace("+00:00", "Z"),
            "observed_state": {"power_state": "powered_off", "description": "A2Z-Control-Plane-Demo"},
        }
        self.expected = {
            field: self.attestation[field] for field in (
                "receipt_id", "task_id", "tenant_id", "target_id", "operation_id",
                "environment", "plan_digest", "lease_generation",
            )
        }

    def tearDown(self):
        self.temp.cleanup()

    def _signed(self):
        openssl = Path("/usr/bin/openssl")
        if not openssl.exists() or openssl.is_symlink():
            self.skipTest("fixed system OpenSSL is unavailable")
        private = self.root / "observer-private.pem"
        trust = self.root / "trust"
        trust.mkdir(mode=0o700)
        generated = subprocess.run(
            [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            check=False, capture_output=True,
        )
        if generated.returncode:
            self.skipTest("system OpenSSL does not support or cannot generate Ed25519 keys")
        private.chmod(0o600)
        public = trust / "observer-key.pem"
        subprocess.run(
            [str(openssl), "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True, capture_output=True,
        )
        signer = Ed25519PostconditionAttestationSigner(
            key_id="observer-key", private_key_path=private, openssl_bin=str(openssl),
        )
        verifier = Ed25519PostconditionAttestationVerifier(
            trust, allowed_verifier_ids=frozenset({"observer-lab-1"}),
            openssl_bin=str(openssl), require_root_owned_trust=False,
        )
        return signer.sign(self.attestation), verifier

    def _structural(self):
        envelope = {
            "attestation": dict(self.attestation),
            "signature": {
                "algorithm": "ed25519", "key_id": "observer-key",
                "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
            },
        }
        verifier = StructuralVerifier(
            self.root / "not-used", allowed_verifier_ids=frozenset({"observer-lab-1"}),
            require_root_owned_trust=False,
        )
        return envelope, verifier

    def test_separate_verifier_key_signs_and_verifies_exact_receipt_scope(self):
        envelope, verifier = self._signed()
        attestation, digest = verifier.verify(envelope, expected_claims=self.expected)
        self.assertEqual(attestation, self.attestation)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_unknown_verifier_identity_is_rejected_before_trust_store_access(self):
        envelope, verifier = self._structural()
        envelope["attestation"]["verifier_id"] = "untrusted-observer"
        with self.assertRaisesRegex(PermissionError, "not enrolled"):
            verifier.verify(envelope, expected_claims=self.expected)

    def test_receipt_binding_mismatch_is_rejected(self):
        envelope, verifier = self._structural()
        wrong_scope = dict(self.expected, receipt_id=str(uuid4()))
        with self.assertRaisesRegex(PermissionError, "receipt_id"):
            verifier.verify(envelope, expected_claims=wrong_scope)

    def test_wrong_observed_state_shape_is_rejected_by_signer(self):
        self.attestation["observed_state"] = {"description": "A2Z-Control-Plane-Demo"}
        openssl = Path("/usr/bin/openssl")
        if not openssl.exists():
            self.skipTest("system OpenSSL is unavailable")
        key = self.root / "unused-key.pem"
        key.write_text("not a key", encoding="utf-8")
        key.chmod(0o600)
        signer = Ed25519PostconditionAttestationSigner(
            key_id="observer-key", private_key_path=key, openssl_bin=str(openssl),
        )
        with self.assertRaisesRegex(ValueError, "typed read-only contract"):
            signer.sign(self.attestation)


if __name__ == "__main__":
    unittest.main()
