from __future__ import annotations

import datetime as dt
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.execution_grants import Ed25519ExecutionGrantVerifier
from control_plane_core.grant_signer_service import (
    GrantSigningPolicy,
    UnixExecutionGrantSigner,
    serve_signing_connection,
)
from control_plane_core.execution_grants import Ed25519ExecutionGrantSigner


class GrantSignerServiceTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.grant = {
            "schema_version": "a2z-execution-grant-v2",
            "grant_id": str(uuid4()), "task_id": str(uuid4()),
            "tenant_id": "lab-tenant", "target_id": "vm-lab-1",
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "plan_digest": "a" * 64, "authorization_mode": "operator_approval",
            "authorization_id": str(uuid4()), "approval_id": None,
            "policy_digest": None, "impact_assessment_digest": None,
            "lease_generation": 1, "runner_id": "runner-lab-1",
            "lease_token_sha256": "b" * 64,
            "issued_at": self.now.isoformat().replace("+00:00", "Z"),
            "expires_at": (self.now + dt.timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
            "max_runtime_seconds": 60,
        }
        self.grant["approval_id"] = self.grant["authorization_id"]
        self.policy = GrantSigningPolicy(
            api_uid=max(1, os.geteuid()), tenant_id="lab-tenant", runner_id="runner-lab-1",
            target_ids=frozenset({"vm-lab-1"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            max_runtime_seconds=120,
        )

    def test_signer_policy_accepts_only_exact_lab_scope_and_bounded_authorization(self):
        self.policy.authorize(self.grant)
        cases = (
            ("target_id", "other-vm"),
            ("operation_id", "shell.exec"),
            ("environment", "production"),
            ("runner_id", "other-runner"),
            ("max_runtime_seconds", 121),
        )
        for field, value in cases:
            candidate = dict(self.grant, **{field: value})
            with self.subTest(field=field), self.assertRaises((ValueError, PermissionError)):
                self.policy.authorize(candidate)

    def test_signer_rejects_invalid_standing_policy_and_expired_authorization(self):
        standing = dict(self.grant, authorization_mode="standing_policy", approval_id=None,
                        policy_digest="c" * 64, impact_assessment_digest="d" * 64)
        self.policy.authorize(standing)
        with self.assertRaisesRegex(PermissionError, "cannot claim operator approval"):
            self.policy.authorize(dict(standing, approval_id=str(uuid4())))
        expired = dict(self.grant, expires_at=(self.now - dt.timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(PermissionError, "expired"):
            self.policy.authorize(expired)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED") and os.geteuid() > 0,
                         "Linux Unix-socket peer credentials and a non-root test user are required")
    def test_unix_signer_holds_key_and_returns_verifiable_scoped_grant(self):
        with tempfile.TemporaryDirectory(prefix="a2z-confined-grant-signer-") as directory:
            root = Path(directory)
            key = root / "issuer.pem"
            public_key = root / "issuer-public.pem"
            generated = subprocess.run(
                ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                check=False, capture_output=True,
            )
            if generated.returncode != 0:
                self.skipTest("fixed /usr/bin/openssl does not provide Ed25519")
            key.chmod(0o600)
            subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_key)], check=True)
            private_signer = Ed25519ExecutionGrantSigner(key, key_id="lab-issuer-v1", require_root_owned_key=False)
            socket_path = root / "issuer.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            socket_path.chmod(0o600)
            listener.listen(1)

            def one_request():
                connection, _ = listener.accept()
                with connection:
                    serve_signing_connection(connection, api_uid=os.geteuid(), policy=self.policy,
                                             signer=private_signer)

            server = threading.Thread(target=one_request, daemon=True)
            server.start()
            client = UnixExecutionGrantSigner(socket_path, expected_signer_uid=os.geteuid(),
                                              key_id="lab-issuer-v1")
            envelope = client.sign(self.grant)
            server.join(timeout=5)
            listener.close()
            self.assertFalse(server.is_alive())

            trust = root / "trust"
            trust.mkdir(mode=0o700)
            (trust / "lab-issuer-v1.pem").write_bytes(public_key.read_bytes())
            verifier = Ed25519ExecutionGrantVerifier(trust, require_root_owned_trust=False)
            expected = {name: self.grant[name] for name in (
                "task_id", "tenant_id", "target_id", "operation_id", "environment", "plan_digest",
                "authorization_mode", "authorization_id", "approval_id", "policy_digest",
                "impact_assessment_digest", "lease_generation", "runner_id", "lease_token_sha256",
            )}
            verified, _digest = verifier.verify(envelope, expected_claims=expected)
            self.assertEqual(verified, self.grant)


if __name__ == "__main__":
    unittest.main()
