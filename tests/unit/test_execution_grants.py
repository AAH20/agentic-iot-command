from __future__ import annotations

import base64
import datetime as dt
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.execution_grants import Ed25519ExecutionGrantSigner, Ed25519ExecutionGrantVerifier, _canonical_payload


class ClaimCheckingGrantVerifier(Ed25519ExecutionGrantVerifier):
    def _verify_signature(self, envelope):
        self.signature_checked = True


class ExecutionGrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-execution-grant-")
        self.verifier = ClaimCheckingGrantVerifier(Path(self.temp.name), require_root_owned_trust=False)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.grant = {
            "schema_version": "a2z-execution-grant-v2",
            "grant_id": str(uuid4()), "task_id": str(uuid4()),
            "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": "virtualbox.vm.start", "environment": "lab",
            "plan_digest": "a" * 64, "authorization_mode": "operator_approval",
            "authorization_id": str(uuid4()), "approval_id": None,
            "policy_digest": None, "impact_assessment_digest": None,
            "lease_generation": 2, "runner_id": "runner-lab-1",
            "lease_token_sha256": "b" * 64,
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + dt.timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
            "max_runtime_seconds": 120,
        }
        self.envelope = {
            "grant": self.grant,
            "signature": {
                "algorithm": "ed25519", "key_id": "control-plane-issuer-v1",
                "signature_base64": base64.b64encode(b"x" * 64).decode("ascii"),
            },
        }
        self.claims = {key: self.grant[key] for key in (
            "task_id", "tenant_id", "target_id", "operation_id", "environment", "plan_digest",
            "authorization_mode", "authorization_id", "approval_id", "policy_digest",
            "impact_assessment_digest", "lease_generation", "runner_id", "lease_token_sha256",
        )}
        self.grant["approval_id"] = self.grant["authorization_id"]
        self.claims["approval_id"] = self.grant["approval_id"]

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_short_lived_lease_grant_is_accepted(self):
        grant, digest = self.verifier.verify(self.envelope, expected_claims=self.claims)
        self.assertEqual(grant, self.grant)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(self.verifier.signature_checked)

    def test_wrong_fencing_generation_or_lease_token_is_rejected(self):
        for field, value in (("lease_generation", 3), ("lease_token_sha256", "c" * 64)):
            with self.subTest(field=field), self.assertRaisesRegex(PermissionError, field):
                self.verifier.verify(self.envelope, expected_claims=dict(self.claims, **{field: value}))
        self.assertFalse(getattr(self.verifier, "signature_checked", False))

    def test_standing_policy_grant_requires_both_signed_evidence_digests_and_no_approval(self):
        self.grant.update({
            "authorization_mode": "standing_policy", "authorization_id": str(uuid4()),
            "approval_id": None, "policy_digest": "c" * 64,
            "impact_assessment_digest": "d" * 64,
        })
        self.claims = {key: self.grant[key] for key in self.claims}
        verified, _ = self.verifier.verify(self.envelope, expected_claims=self.claims)
        self.assertEqual(verified["authorization_mode"], "standing_policy")
        self.assertIsNone(verified["approval_id"])

        self.grant["approval_id"] = str(uuid4())
        with self.assertRaisesRegex(PermissionError, "must not claim a human approval"):
            self.verifier.verify(self.envelope, expected_claims=dict(self.claims, approval_id=self.grant["approval_id"]))
        self.grant["approval_id"] = None
        self.grant["impact_assessment_digest"] = "not-a-digest"
        with self.assertRaisesRegex(PermissionError, "impact_assessment_digest"):
            self.verifier.verify(self.envelope, expected_claims=dict(self.claims, impact_assessment_digest="not-a-digest"))

    def test_expired_grant_and_production_grant_are_rejected(self):
        self.grant["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(PermissionError, "expired"):
            self.verifier.verify(self.envelope, expected_claims=self.claims)
        self.grant["environment"] = "production"
        self.claims["environment"] = "production"
        with self.assertRaisesRegex(PermissionError, "non-production"):
            self.verifier.verify(self.envelope, expected_claims=self.claims)

    def test_runtime_and_wildcard_limits_are_enforced(self):
        self.grant["max_runtime_seconds"] = 301
        with self.assertRaisesRegex(PermissionError, "5-minute"):
            self.verifier.verify(self.envelope, expected_claims=self.claims)
        self.grant["max_runtime_seconds"] = 120
        self.grant["target_id"] = "*"
        with self.assertRaisesRegex(ValueError, "specific bounded"):
            self.verifier.verify(self.envelope, expected_claims=self.claims)

    def test_ed25519_signer_produces_a_verifiable_domain_separated_signature(self):
        with tempfile.TemporaryDirectory(prefix="a2z-grant-signing-test-") as directory:
            private_key = Path(directory) / "issuer.pem"
            public_key = Path(directory) / "issuer-public.pem"
            generated = subprocess.run(
                ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                check=False, capture_output=True,
            )
            if generated.returncode != 0:
                self.skipTest("fixed /usr/bin/openssl does not provide Ed25519 support on this host")
            os.chmod(private_key, 0o600)
            subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True)
            signer = Ed25519ExecutionGrantSigner(private_key, key_id="test-issuer", require_root_owned_key=False)
            envelope = signer.sign(self.grant)
            payload = Path(directory) / "payload.json"
            signature = Path(directory) / "signature.bin"
            payload.write_bytes(_canonical_payload(self.grant))
            signature.write_bytes(base64.b64decode(envelope["signature"]["signature_base64"], validate=True))
            subprocess.run([
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-rawin",
                "-in", str(payload), "-sigfile", str(signature),
            ], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
