from __future__ import annotations

import ssl
import unittest
import hashlib
import subprocess
import tempfile
import errno
from dataclasses import replace
from pathlib import Path
from threading import Thread
from uuid import uuid4

from control_plane_core.worker_api import (
    AuthenticatedWorkerAPI,
    MTLSWorkerClient,
    RunnerCertificateRegistry,
    RunnerIdentity,
    build_mtls_worker_server,
    mtls_server_context,
)


class FakeStore:
    def __init__(self):
        self.task_id = str(uuid4())
        self.token = "lease-secret"
        self.calls = []
        self.task = {
            "task_id": self.task_id, "tenant_id": "lab-tenant",
            "target_ids": ["vm-1"], "operation_id": "virtualbox.vm.set_demo_description",
            "environment": "lab", "plan_digest": "a" * 64,
            "plan": {"max_runtime_seconds": 30},
        }

    def get_task(self, *, task_id, tenant_id):
        self.calls.append(("get_task", task_id, tenant_id))
        if task_id != self.task_id or tenant_id != "lab-tenant":
            raise KeyError("task not found")
        return dict(self.task)

    def claim_execution_lease(self, **kwargs):
        self.calls.append(("claim", kwargs))
        return {"status": "leased", "lease_generation": 3,
                "lease_until": "2030-01-01T00:00:00Z", "lease_token": self.token}

    def get_current_execution_lease(self, **kwargs):
        self.calls.append(("lease", kwargs))
        if kwargs["runner_id"] != "runner-1":
            raise PermissionError("wrong runner")
        return {"lease_token": self.token}

    def get_current_execution_token(self, **kwargs):
        self.calls.append(("active_token", kwargs))
        return {"lease_token": self.token, "status": "running"}

    def issue_execution_grant(self, **kwargs):
        self.calls.append(("grant", kwargs))
        return {"grant": {"grant": {"grant_id": str(uuid4())}}, "execution_permitted": False}

    def start_leased_task(self, **kwargs):
        self.calls.append(("consume", kwargs))
        return {"permit_consumed": True, "grant_digest": kwargs["expected_grant_digest"]}

    def record_runner_attestation(self, **kwargs):
        self.calls.append(("attestation", kwargs))
        return {"status": "verified_evidence_only", "execution_permitted": False}

    def reconcile_late_runner_attestation(self, **kwargs):
        self.calls.append(("reconcile_attestation", kwargs))
        return {"status": "verified_evidence_only", "execution_permitted": False}

    def list_ready_execution_tasks(self, **kwargs):
        self.calls.append(("ready", kwargs))
        return [{
            "task_id": self.task_id, "operation_id": self.task["operation_id"],
            "target_ids": ["vm-1"], "environment": "lab",
            "plan_digest": self.task["plan_digest"], "created_at": "2030-01-01T00:00:00Z",
        }]


class WorkerApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-worker-api-")
        self.spiffe = "spiffe://a2z.example/tenant/lab-tenant/runner/runner-1"
        self.certificate_der = b"locally-reviewed-certificate-fixture"
        self.principal = RunnerIdentity(
            spiffe_id=self.spiffe, tenant_id="lab-tenant", runner_id="runner-1",
            certificate_sha256=hashlib.sha256(self.certificate_der).hexdigest(),
            target_ids=frozenset({"vm-1"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            environments=frozenset({"lab"}),
        )
        self.registry = RunnerCertificateRegistry({self.spiffe: self.principal})
        self.store = FakeStore()
        self.api = AuthenticatedWorkerAPI(
            store=self.store, approval_verifier=object(), autonomy_profile_verifier=object(),
            impact_verifier=object(), grant_signer=object(), grant_verifier=object(),
            attestation_verifier=object(),
            execution_control=object(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_certificate_uri_maps_to_server_owned_identity_and_rejects_spoofed_sans(self):
        peer = {"subjectAltName": (("URI", self.spiffe), ("DNS", "runner.local"))}
        self.assertIs(self.registry.resolve_peer_certificate(peer, self.certificate_der), self.principal)
        with self.assertRaisesRegex(PermissionError, "exactly one URI"):
            self.registry.resolve_peer_certificate({"subjectAltName": (("URI", self.spiffe), ("URI", self.spiffe))}, self.certificate_der)
        with self.assertRaisesRegex(PermissionError, "not enrolled"):
            self.registry.resolve_peer_certificate({"subjectAltName": (("URI", "spiffe://unknown/runner/x"),)}, self.certificate_der)
        with self.assertRaisesRegex(PermissionError, "certificate is required"):
            self.registry.resolve_peer_certificate(None, self.certificate_der)
        with self.assertRaisesRegex(PermissionError, "fingerprint has been revoked"):
            self.registry.resolve_peer_certificate(peer, b"rotated-certificate")

    def test_claim_derives_tenant_and_runner_from_principal_and_returns_scoped_lease(self):
        lease = self.api.claim(principal=self.principal, task_id=self.store.task_id)
        self.assertEqual(lease["tenant_id"], "lab-tenant")
        self.assertEqual(lease["runner_id"], "runner-1")
        self.assertEqual(lease["lease_token"], self.store.token)
        claim = next(call[1] for call in self.store.calls if call[0] == "claim")
        self.assertEqual(claim["tenant_id"], "lab-tenant")
        self.assertEqual(claim["worker_id"], "runner-1")
        self.assertEqual(claim["autonomy_profile_verifier"], self.api.autonomy_profile_verifier)

    def test_ready_queue_is_scoped_to_authenticated_runner_and_contains_no_plan_or_lease(self):
        result = self.api.ready_tasks(principal=self.principal)
        self.assertEqual(len(result["tasks"]), 1)
        self.assertNotIn("plan", result["tasks"][0])
        self.assertNotIn("lease_token", result["tasks"][0])
        call = next(call[1] for call in self.store.calls if call[0] == "ready")
        self.assertEqual(call["tenant_id"], "lab-tenant")
        self.assertEqual(call["target_ids"], frozenset({"vm-1"}))
        self.assertEqual(call["operation_ids"], frozenset({"virtualbox.vm.set_demo_description"}))

    def test_scope_denial_precedes_journal_lease_claim(self):
        principal = replace(self.principal, target_ids=frozenset({"other-vm"}))
        with self.assertRaisesRegex(PermissionError, "outside the authenticated runner"):
            self.api.claim(principal=principal, task_id=self.store.task_id)
        self.assertFalse(any(call[0] == "claim" for call in self.store.calls))

    def test_grant_and_consumption_require_current_lease_token_and_exact_digest(self):
        envelope = self.api.issue_grant(
            principal=self.principal, task_id=self.store.task_id, lease_token=self.store.token,
        )
        self.assertIn("grant", envelope)
        grant_call = next(call[1] for call in self.store.calls if call[0] == "grant")
        self.assertEqual(grant_call["tenant_id"], "lab-tenant")

        with self.assertRaisesRegex(PermissionError, "current lease token"):
            self.api.consume_permit(
                principal=self.principal, task_id=self.store.task_id,
                lease_token="forged", grant_digest="b" * 64,
            )
        accepted = self.api.consume_permit(
            principal=self.principal, task_id=self.store.task_id,
            lease_token=self.store.token, grant_digest="b" * 64,
        )
        self.assertEqual(accepted, {
            "task_id": self.store.task_id, "runner_id": "runner-1",
            "grant_digest": "b" * 64, "permit_consumed": True,
        })
        consume_call = next(call[1] for call in self.store.calls if call[0] == "consume")
        self.assertEqual(consume_call["authenticated_runner_id"], "runner-1")
        self.assertEqual(consume_call["expected_grant_digest"], "b" * 64)

    def test_mtls_server_refuses_optional_client_authentication(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_OPTIONAL
        with self.assertRaisesRegex(PermissionError, "require mutual TLS"):
            build_mtls_worker_server(api=self.api, registry=self.registry, tls_context=context)

    def test_signed_attestation_submission_uses_active_lease_and_never_marks_task_complete(self):
        envelope = {"attestation": {"signed": "receipt"}, "signature": {
            "algorithm": "ed25519", "key_id": "runner-1", "signature_base64": "c2ln",
        }}
        with self.assertRaisesRegex(PermissionError, "current lease token"):
            self.api.submit_attestation(
                principal=self.principal, task_id=self.store.task_id, lease_token="forged",
                signed_attestation=envelope,
            )
        result = self.api.submit_attestation(
            principal=self.principal, task_id=self.store.task_id, lease_token=self.store.token,
            signed_attestation=envelope,
        )
        self.assertEqual(result["status"], "verified_evidence_only")
        self.assertFalse(result["execution_permitted"])
        record = next(call[1] for call in self.store.calls if call[0] == "attestation")
        self.assertEqual(record["signed_attestation"], envelope)
        self.assertEqual(record["verifier"], self.api.attestation_verifier)

    def test_late_receipt_reconciliation_uses_certificate_identity_without_lease_token(self):
        envelope = {"attestation": {"signed": "historical-receipt"}, "signature": {
            "algorithm": "ed25519", "key_id": "runner-1", "signature_base64": "c2ln",
        }}
        self.api.reconcile_attestation(
            principal=self.principal, task_id=self.store.task_id, signed_attestation=envelope,
        )
        call = next(call[1] for call in self.store.calls if call[0] == "reconcile_attestation")
        self.assertEqual(call["runner_id"], self.principal.runner_id)
        self.assertEqual(call["tenant_id"], self.principal.tenant_id)
        self.assertEqual(call["signed_attestation"], envelope)
        self.assertNotIn("lease_token", call)
        mismatched = {"attestation": {}, "signature": {
            "algorithm": "ed25519", "key_id": "another-runner", "signature_base64": "c2ln",
        }}
        calls_before = len(self.store.calls)
        with self.assertRaisesRegex(PermissionError, "key ID must match"):
            self.api.reconcile_attestation(
                principal=self.principal, task_id=self.store.task_id, signed_attestation=mismatched,
            )
        self.assertEqual(len(self.store.calls), calls_before + 1)  # only the tenant-scoped lookup occurred

    def test_worker_client_reconciliation_route_sends_only_the_signed_receipt(self):
        client = object.__new__(MTLSWorkerClient)
        calls = []
        client._request = lambda method, path, body: calls.append((method, path, body)) or {"ok": True}
        envelope = {"attestation": {"receipt_id": "receipt"}, "signature": {"key_id": "runner-1"}}
        result = client.reconcile_attestation(task_id=self.store.task_id, signed_attestation=envelope)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(calls, [(
            "POST", f"/v1/tasks/{self.store.task_id}/reconcile-attestation",
            {"signed_attestation": envelope},
        )])

    def test_real_mtls_client_reaches_only_the_certificate_scoped_worker_route(self):
        openssl = Path("/usr/bin/openssl")
        if not openssl.is_file():
            self.skipTest("system OpenSSL is unavailable")
        root = Path(self.temp.name)

        def run(*args):
            subprocess.run(
                [str(openssl), *args], check=True, capture_output=True,
                timeout=15, cwd=root,
            )

        ca_key, ca_cert = root / "ca.key", root / "ca.pem"
        server_key, server_csr, server_cert = root / "server.key", root / "server.csr", root / "server.pem"
        client_key, client_csr, client_cert = root / "client.key", root / "client.csr", root / "client.pem"
        server_ext, client_ext = root / "server.ext", root / "client.ext"
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
            "-out", str(ca_cert), "-days", "2", "-subj", "/CN=A2Z-test-CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(server_key),
            "-out", str(server_csr), "-subj", "/CN=localhost")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(client_key),
            "-out", str(client_csr), "-subj", "/CN=runner-1")
        server_ext.write_text(
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        )
        client_ext.write_text(
            "subjectAltName=URI:spiffe://a2z.example/tenant/lab-tenant/runner/runner-1\n"
            "extendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid,issuer\n"
        )
        run("x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(server_cert), "-days", "2", "-extfile", str(server_ext))
        run("x509", "-req", "-in", str(client_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(client_cert), "-days", "2", "-extfile", str(client_ext))
        for key in (ca_key, server_key, client_key):
            key.chmod(0o600)
        client_der = ssl.PEM_cert_to_DER_cert(client_cert.read_text())
        principal = replace(
            self.principal, certificate_sha256=hashlib.sha256(client_der).hexdigest(),
        )
        registry = RunnerCertificateRegistry({principal.spiffe_id: principal})
        context = mtls_server_context(
            certificate=str(server_cert), private_key=str(server_key),
            client_ca=str(ca_cert), require_root_owned=False,
        )
        try:
            server = build_mtls_worker_server(
                api=self.api, registry=registry, tls_context=context,
                address=("127.0.0.1", 0),
            )
        except OSError as exc:
            if exc.errno in {errno.EPERM, errno.EACCES}:
                self.skipTest("sandbox policy blocks loopback listener creation")
            raise
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = MTLSWorkerClient(
                base_url=f"https://127.0.0.1:{server.server_port}", runner_id="runner-1",
                client_certificate=str(client_cert), client_private_key=str(client_key),
                server_ca=str(ca_cert),
            )
            lease = client.claim(task_id=self.store.task_id)
            self.assertEqual(lease["runner_id"], "runner-1")
            self.assertEqual(lease["tenant_id"], "lab-tenant")
            self.assertEqual(lease["lease_token"], self.store.token)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
