from __future__ import annotations

import hashlib
import ssl
import unittest
import subprocess
import tempfile
import errno
from dataclasses import replace
from pathlib import Path
from threading import Thread
from uuid import uuid4

from control_plane_core.postcondition_api import (
    AuthenticatedPostconditionAPI,
    MTLSPostconditionClient,
    PostconditionVerifierCertificateRegistry,
    PostconditionVerifierIdentity,
    build_mtls_postcondition_server,
)
from control_plane_core.worker_api import mtls_server_context


class FakeStore:
    def __init__(self):
        self.task_id = str(uuid4())
        self.calls = []
        self.candidate = {
            "task_id": self.task_id, "tenant_id": "lab-tenant", "target_id": "vm-1",
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "plan_digest": "a" * 64, "lease_generation": 1,
            "plan": {"desired_state": {"description": "demo"}},
            "runner_attestation": {"attestation": {"receipt_id": str(uuid4())}},
            "runner_attestation_sha256": "b" * 64,
        }

    def get_postcondition_candidate(self, *, task_id, tenant_id):
        self.calls.append(("candidate", task_id, tenant_id))
        if task_id != self.task_id or tenant_id != "lab-tenant":
            raise KeyError("task not found")
        return dict(self.candidate)

    def list_postcondition_candidates(self, **kwargs):
        self.calls.append(("list", kwargs))
        if kwargs["tenant_id"] != "lab-tenant":
            raise PermissionError("wrong tenant")
        if ("vm-1" not in kwargs["target_ids"]
                or "virtualbox.vm.set_demo_description" not in kwargs["operation_ids"]
                or "lab" not in kwargs["environments"]):
            return []
        return [{
            "task_id": self.task_id, "tenant_id": "lab-tenant",
            "operation_id": "virtualbox.vm.set_demo_description",
            "target_id": "vm-1", "environment": "lab", "plan_digest": "a" * 64,
            "updated_at": "2030-01-01T00:00:00Z",
        }][:kwargs["limit"]]

    def record_postcondition_attestation(self, **kwargs):
        self.calls.append(("submit", kwargs))
        return {"task_id": kwargs["task_id"], "status": "completed", "verified": True}


class PostconditionApiTests(unittest.TestCase):
    def setUp(self):
        self.der = b"postcondition verifier certificate fixture"
        self.spiffe = "spiffe://a2z.example/tenant/lab-tenant/verifier/observer-1"
        self.principal = PostconditionVerifierIdentity(
            spiffe_id=self.spiffe, verifier_id="observer-1", tenant_id="lab-tenant",
            certificate_sha256=hashlib.sha256(self.der).hexdigest(),
            target_ids=frozenset({"vm-1"}),
            operation_ids=frozenset({"virtualbox.vm.set_demo_description"}),
            environments=frozenset({"lab"}),
        )
        self.registry = PostconditionVerifierCertificateRegistry({self.spiffe: self.principal})
        self.store = FakeStore()
        self.api = AuthenticatedPostconditionAPI(store=self.store, verifier=object())

    def _envelope(self):
        return {"attestation": {
            "task_id": self.store.task_id, "tenant_id": "lab-tenant", "target_id": "vm-1",
            "operation_id": "virtualbox.vm.set_demo_description", "environment": "lab",
            "verifier_id": "observer-1",
        }, "signature": {"algorithm": "ed25519"}}

    def test_certificate_registry_requires_exact_uri_and_pinned_fingerprint(self):
        self.assertIs(self.registry.resolve_peer_certificate(
            {"subjectAltName": (("URI", self.spiffe),)}, self.der), self.principal)
        with self.assertRaisesRegex(PermissionError, "exactly one URI"):
            self.registry.resolve_peer_certificate(
                {"subjectAltName": (("URI", self.spiffe), ("URI", self.spiffe))}, self.der)
        with self.assertRaisesRegex(PermissionError, "not enrolled"):
            self.registry.resolve_peer_certificate(
                {"subjectAltName": (("URI", "spiffe://unknown/verifier"),)}, self.der)
        with self.assertRaisesRegex(PermissionError, "fingerprint"):
            self.registry.resolve_peer_certificate({"subjectAltName": (("URI", self.spiffe),)}, b"rotated")

    def test_candidate_read_is_derived_from_certificate_tenant_and_exact_scope(self):
        result = self.api.get_candidate(principal=self.principal, task_id=self.store.task_id)
        self.assertEqual(result["task_id"], self.store.task_id)
        self.assertEqual(self.store.calls, [("candidate", self.store.task_id, "lab-tenant")])
        outside = replace(self.principal, target_ids=frozenset({"other-vm"}))
        with self.assertRaisesRegex(PermissionError, "outside the authenticated verifier scope"):
            self.api.get_candidate(principal=outside, task_id=self.store.task_id)
        page = self.api.list_candidates(principal=self.principal, limit=1)
        self.assertEqual(page["tasks"][0]["task_id"], self.store.task_id)
        self.assertEqual(self.store.calls[-1][1]["target_ids"], frozenset({"vm-1"}))

    def test_submission_binds_authenticated_verifier_task_and_scope(self):
        result = self.api.submit_attestation(
            principal=self.principal, task_id=self.store.task_id, signed_attestation=self._envelope(),
        )
        self.assertEqual(result["status"], "completed")
        call = self.store.calls[-1][1]
        self.assertEqual(call["tenant_id"], "lab-tenant")
        self.assertIs(call["verifier"], self.api.verifier)
        envelope = self._envelope()
        envelope["attestation"]["verifier_id"] = "other-verifier"
        with self.assertRaisesRegex(PermissionError, "differs from authenticated verifier"):
            self.api.submit_attestation(
                principal=self.principal, task_id=self.store.task_id, signed_attestation=envelope,
            )
        outside = replace(self.principal, operation_ids=frozenset({"other.operation"}))
        with self.assertRaisesRegex(PermissionError, "outside the authenticated verifier scope"):
            self.api.submit_attestation(
                principal=outside, task_id=self.store.task_id, signed_attestation=self._envelope(),
            )

    def test_api_refuses_optional_client_authentication_and_wildcard_bind(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_OPTIONAL
        with self.assertRaisesRegex(PermissionError, "require mutual TLS"):
            build_mtls_postcondition_server(api=self.api, registry=self.registry, tls_context=context)
        context.verify_mode = ssl.CERT_REQUIRED
        with self.assertRaisesRegex(PermissionError, "loopback"):
            build_mtls_postcondition_server(
                api=self.api, registry=self.registry, tls_context=context, address=("0.0.0.0", 9444),
            )

    def test_production_verifier_scope_is_rejected(self):
        with self.assertRaisesRegex(PermissionError, "production environments"):
            replace(self.principal, environments=frozenset({"production"}))

    def test_real_mtls_client_can_only_fetch_and_submit_scoped_postcondition(self):
        openssl = Path("/usr/bin/openssl")
        if not openssl.is_file():
            self.skipTest("system OpenSSL is unavailable")
        with tempfile.TemporaryDirectory(prefix="a2z-postcondition-mtls-") as temporary:
            root = Path(temporary)

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
                "-out", str(client_csr), "-subj", "/CN=observer-1")
            server_ext.write_text(
                "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
                "authorityKeyIdentifier=keyid,issuer\n"
            )
            client_ext.write_text(
                "subjectAltName=URI:spiffe://a2z.example/tenant/lab-tenant/verifier/observer-1\n"
                "extendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid,issuer\n"
            )
            run("x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(server_cert), "-days", "2", "-extfile", str(server_ext))
            run("x509", "-req", "-in", str(client_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(client_cert), "-days", "2", "-extfile", str(client_ext))
            for key in (ca_key, server_key, client_key):
                key.chmod(0o600)
            client_der = ssl.PEM_cert_to_DER_cert(client_cert.read_text())
            principal = replace(self.principal, certificate_sha256=hashlib.sha256(client_der).hexdigest())
            registry = PostconditionVerifierCertificateRegistry({principal.spiffe_id: principal})
            context = mtls_server_context(
                certificate=str(server_cert), private_key=str(server_key),
                client_ca=str(ca_cert), require_root_owned=False,
            )
            try:
                server = build_mtls_postcondition_server(
                    api=self.api, registry=registry, tls_context=context, address=("127.0.0.1", 0),
                )
            except OSError as exc:
                if exc.errno in {errno.EPERM, errno.EACCES}:
                    self.skipTest("sandbox policy blocks loopback listener creation")
                raise
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = MTLSPostconditionClient(
                    base_url=f"https://127.0.0.1:{server.server_port}",
                    verifier_id="observer-1", tenant_id="lab-tenant",
                    client_certificate=str(client_cert), client_private_key=str(client_key),
                    server_ca=str(ca_cert),
                )
                candidate = client.get_postcondition_candidate(
                    task_id=self.store.task_id, tenant_id="lab-tenant",
                )
                self.assertEqual(candidate["task_id"], self.store.task_id)
                ready = client.list_postcondition_candidates(limit=2)
                self.assertEqual([item["task_id"] for item in ready], [self.store.task_id])
                result = client.record_postcondition_attestation(
                    task_id=self.store.task_id, tenant_id="lab-tenant", signed_attestation=self._envelope(),
                )
                self.assertEqual(result["status"], "completed")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
