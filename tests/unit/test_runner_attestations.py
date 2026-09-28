from __future__ import annotations

import base64
import datetime as dt
import subprocess
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.runner_attestations import (
    Ed25519RunnerAttestationSigner, Ed25519RunnerAttestationVerifier,
)


class ValidatingRunnerVerifier(Ed25519RunnerAttestationVerifier):
    def _verify_signature(self, envelope):
        self.signature_checked = True


class RunnerAttestationVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-runner-attest-")
        self.verifier = ValidatingRunnerVerifier(Path(self.temp.name), require_root_owned_trust=False)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.attestation = {
            "schema_version": "a2z-runner-attestation-v1",
            "receipt_id": str(uuid4()),
            "task_id": str(uuid4()),
            "tenant_id": "lab-tenant",
            "target_id": "vm-lab-1",
            "operation_id": "virtualbox.vm.start",
            "environment": "lab",
            "plan_digest": "a" * 64,
            "lease_generation": 3,
            "runner_id": "runner-lab-1",
            "started_at": (now - dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
            "completed_at": now.isoformat().replace("+00:00", "Z"),
            "outcome": "succeeded",
            "changed": True,
            "pre_state_sha256": "b" * 64,
            "post_state_sha256": "c" * 64,
            "network_calls": 1,
            "credentials_issued": False,
        }
        self.envelope = {
            "attestation": self.attestation,
            "signature": {
                "algorithm": "ed25519", "key_id": "lab-runner-v1",
                "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
            },
        }
        self.expected = {
            field: self.attestation[field]
            for field in ("task_id", "tenant_id", "target_id", "operation_id", "environment",
                          "plan_digest", "lease_generation", "runner_id")
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_task_claims_are_validated_before_signature_verification(self):
        attestation, digest = self.verifier.verify(self.envelope, expected_claims=self.expected)
        self.assertEqual(attestation, self.attestation)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(self.verifier.signature_checked)

    def test_historical_verification_allows_old_signed_evidence_only_through_explicit_path(self):
        old = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(hours=2)
        self.attestation["started_at"] = (old - dt.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
        self.attestation["completed_at"] = old.isoformat().replace("+00:00", "Z")
        with self.assertRaisesRegex(PermissionError, "freshness window"):
            self.verifier.verify(self.envelope, expected_claims=self.expected)
        attestation, digest = self.verifier.verify_historical(
            self.envelope, expected_claims=self.expected,
        )
        self.assertEqual(attestation, self.attestation)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(self.verifier.signature_checked)

    def test_wrong_lease_generation_is_rejected(self):
        claims = dict(self.expected, lease_generation=4)
        with self.assertRaisesRegex(PermissionError, "lease_generation"):
            self.verifier.verify(self.envelope, expected_claims=claims)
        self.assertFalse(getattr(self.verifier, "signature_checked", False))

    def test_malformed_signature_encoding_is_rejected(self):
        self.envelope["signature"]["signature_base64"] = "not-base64!"
        with self.assertRaisesRegex(ValueError, "encoding is invalid"):
            self.verifier.verify(self.envelope, expected_claims=self.expected)

    def test_production_environment_is_rejected(self):
        self.attestation["environment"] = "production"
        with self.assertRaisesRegex(PermissionError, "outside the lab"):
            self.verifier.verify(self.envelope, expected_claims=self.expected)

    def test_runner_signer_emits_verifiable_domain_separated_ed25519_receipt(self):
        openssl = Path("/usr/bin/openssl")
        if not openssl.exists() or openssl.is_symlink():
            self.skipTest("fixed system OpenSSL is unavailable")
        key = Path(self.temp.name) / "runner-private.pem"
        public_key = Path(self.temp.name) / "runner-public.pem"
        generated = subprocess.run(
            [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(key)],
            check=False, capture_output=True,
        )
        if generated.returncode:
            self.skipTest("system OpenSSL does not support Ed25519")
        key.chmod(0o600)
        subprocess.run(
            [str(openssl), "pkey", "-in", str(key), "-pubout", "-out", str(public_key)],
            check=True, capture_output=True,
        )
        signer = Ed25519RunnerAttestationSigner(
            key_id="lab-runner-v1", private_key_path=key, openssl_bin=str(openssl),
        )
        envelope = signer.sign(self.attestation)
        self.assertEqual(envelope["attestation"], self.attestation)
        self.assertEqual(envelope["signature"]["algorithm"], "ed25519")
        signature = Path(self.temp.name) / "signature.bin"
        payload = Path(self.temp.name) / "payload.json"
        from control_plane_core.runner_attestations import _canonical_envelope_payload
        signature.write_bytes(base64.b64decode(envelope["signature"]["signature_base64"], validate=True))
        payload.write_bytes(_canonical_envelope_payload(self.attestation))
        checked = subprocess.run(
            [str(openssl), "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-rawin", "-in", str(payload), "-sigfile", str(signature)],
            check=False, capture_output=True,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors="replace"))

    def test_runner_signer_rejects_group_or_other_readable_private_key(self):
        key = Path(self.temp.name) / "not-private.pem"
        key.write_text("not a key", encoding="utf-8")
        key.chmod(0o644)
        signer = Ed25519RunnerAttestationSigner(key_id="lab-runner-v1", private_key_path=key)
        with self.assertRaisesRegex(PermissionError, "inaccessible to group/other"):
            signer.sign(self.attestation)


if __name__ == "__main__":
    unittest.main()
