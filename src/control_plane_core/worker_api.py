from __future__ import annotations

import re
import ssl
import json
import hashlib
import os
import stat
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_target(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip()) and value != "*"
            and len(value) <= 512 and not any(ord(character) < 32 for character in value))


@dataclass(frozen=True)
class RunnerIdentity:
    """Server-side identity and exact scope mapped from a trusted client certificate."""

    spiffe_id: str
    tenant_id: str
    runner_id: str
    certificate_sha256: str
    target_ids: frozenset[str]
    operation_ids: frozenset[str]
    environments: frozenset[str]

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and _SAFE_ID.fullmatch(value)
                   for value in (self.tenant_id, self.runner_id)):
            raise ValueError("runner tenant and identity must be specific bounded identifiers")
        if not isinstance(self.spiffe_id, str) or not self.spiffe_id.startswith("spiffe://"):
            raise ValueError("runner identity must have a SPIFFE URI")
        if not isinstance(self.certificate_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.certificate_sha256):
            raise ValueError("runner identity must pin the reviewed TLS certificate SHA-256")
        if (not isinstance(self.target_ids, frozenset) or not self.target_ids
                or any(not _safe_target(value) for value in self.target_ids)):
            raise ValueError("runner target_ids must be a non-empty exact allowlist")
        if (not isinstance(self.operation_ids, frozenset) or not self.operation_ids
                or any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value)
                       for value in self.operation_ids)):
            raise ValueError("runner operation_ids must be a non-empty code-style allowlist")
        if (not isinstance(self.environments, frozenset) or not self.environments
                or not self.environments.issubset({"lab", "development", "staging"})):
            raise ValueError("runner environments must be a non-empty non-production allowlist")


class RunnerCertificateRegistry:
    """Maps verified TLS certificate URI SANs to root-configured runner scopes."""

    def __init__(self, identities: Mapping[str, RunnerIdentity]) -> None:
        if not isinstance(identities, Mapping) or not identities:
            raise ValueError("at least one reviewed runner certificate identity is required")
        self._identities = dict(identities)
        for uri, identity in self._identities.items():
            if not isinstance(identity, RunnerIdentity) or uri != identity.spiffe_id:
                raise ValueError("runner certificate registry key must equal its configured SPIFFE ID")

    def resolve_peer_certificate(self, certificate: Mapping[str, Any] | None,
                                 certificate_der: bytes | None = None) -> RunnerIdentity:
        """Resolve only a TLS-verified peer certificate; caller fields are not identity."""
        if not isinstance(certificate, Mapping):
            raise PermissionError("mutually authenticated runner certificate is required")
        if not isinstance(certificate_der, bytes) or not certificate_der:
            raise PermissionError("runner certificate fingerprint is unavailable")
        sans = certificate.get("subjectAltName")
        if not isinstance(sans, (list, tuple)):
            raise PermissionError("runner certificate has no subject alternative names")
        if any(not isinstance(item, (list, tuple)) or len(item) != 2 for item in sans):
            raise PermissionError("runner certificate SAN encoding is invalid")
        uris = [value for kind, value in sans if kind == "URI"]
        if len(uris) != 1 or not isinstance(uris[0], str):
            raise PermissionError("runner certificate must contain exactly one URI identity")
        identity = self._identities.get(uris[0])
        if identity is None:
            raise PermissionError("runner certificate identity is not enrolled")
        if hashlib.sha256(certificate_der).hexdigest() != identity.certificate_sha256:
            raise PermissionError("runner certificate fingerprint has been revoked or rotated")
        return identity


class AuthenticatedWorkerAPI:
    """Typed worker operations; HTTP/TLS layer must resolve the principal first.

    The API accepts no tenant or runner identity from the request body. Each
    operation checks exact target, action, environment, and tenant membership
    against the certificate-derived RunnerIdentity before touching the journal.
    """

    def __init__(self, *, store: Any, approval_verifier: Any,
                 autonomy_profile_verifier: Any, impact_verifier: Any,
                 grant_signer: Any, grant_verifier: Any, attestation_verifier: Any,
                 execution_control: Any) -> None:
        dependencies = (store, grant_signer, grant_verifier, attestation_verifier, execution_control)
        if any(dependency is None for dependency in dependencies):
            raise PermissionError("worker API requires grant/receipt trust, a journal, and execution kill switch")
        self.store = store
        self.approval_verifier = approval_verifier
        self.autonomy_profile_verifier = autonomy_profile_verifier
        self.impact_verifier = impact_verifier
        self.grant_signer = grant_signer
        self.grant_verifier = grant_verifier
        self.attestation_verifier = attestation_verifier
        self.execution_control = execution_control

    def claim(self, *, principal: RunnerIdentity, task_id: str, lease_seconds: int = 60) -> dict[str, Any]:
        task = self._scoped_task(principal, task_id)
        lease = self.store.claim_execution_lease(
            task_id=task_id, tenant_id=principal.tenant_id, worker_id=principal.runner_id,
            approval_verifier=self.approval_verifier,
            autonomy_profile_verifier=self.autonomy_profile_verifier,
            impact_verifier=self.impact_verifier, lease_seconds=lease_seconds,
        )
        # Return the lease secret only once, over the authenticated worker channel.
        return {
            "task_id": task_id, "tenant_id": principal.tenant_id,
            "runner_id": principal.runner_id, "status": lease["status"],
            "lease_generation": lease["lease_generation"],
            "lease_until": lease["lease_until"], "lease_token": lease["lease_token"],
            "plan_digest": task["plan_digest"], "plan": task["plan"],
        }

    def current_lease(self, *, principal: RunnerIdentity, task_id: str) -> dict[str, Any]:
        self._scoped_task(principal, task_id)
        return self.store.get_current_execution_lease(
            task_id=task_id, tenant_id=principal.tenant_id, runner_id=principal.runner_id,
            approval_verifier=self.approval_verifier,
            autonomy_profile_verifier=self.autonomy_profile_verifier,
            impact_verifier=self.impact_verifier,
        )

    def ready_tasks(self, *, principal: RunnerIdentity, limit: int = 50) -> dict[str, Any]:
        if not isinstance(principal, RunnerIdentity):
            raise PermissionError("runner identity must come from the authenticated TLS peer")
        tasks = self.store.list_ready_execution_tasks(
            tenant_id=principal.tenant_id, target_ids=principal.target_ids,
            operation_ids=principal.operation_ids, environments=principal.environments,
            limit=limit,
        )
        for task in tasks:
            if (not set(task.get("target_ids", ())).issubset(principal.target_ids)
                    or task.get("operation_id") not in principal.operation_ids
                    or task.get("environment") not in principal.environments):
                raise PermissionError("ready queue returned a task outside runner scope")
        return {"tasks": tasks}

    def issue_grant(self, *, principal: RunnerIdentity, task_id: str,
                    lease_token: str) -> dict[str, Any]:
        self._assert_lease_token(principal, task_id, lease_token)
        return self.store.issue_execution_grant(
            task_id=task_id, tenant_id=principal.tenant_id, lease_token=lease_token,
            approval_verifier=self.approval_verifier,
            autonomy_profile_verifier=self.autonomy_profile_verifier,
            impact_verifier=self.impact_verifier, grant_signer=self.grant_signer,
            grant_verifier=self.grant_verifier, execution_control=self.execution_control,
        )

    def consume_permit(self, *, principal: RunnerIdentity, task_id: str,
                       lease_token: str, grant_digest: str) -> dict[str, Any]:
        self._assert_lease_token(principal, task_id, lease_token)
        result = self.store.start_leased_task(
            task_id=task_id, tenant_id=principal.tenant_id, lease_token=lease_token,
            authenticated_runner_id=principal.runner_id,
            approval_verifier=self.approval_verifier,
            autonomy_profile_verifier=self.autonomy_profile_verifier,
            impact_verifier=self.impact_verifier, expected_grant_digest=grant_digest,
            grant_verifier=self.grant_verifier, execution_control=self.execution_control,
        )
        if result.get("grant_digest") != grant_digest or result.get("permit_consumed") is not True:
            raise PermissionError("journal did not confirm consumption of the requested grant")
        return {
            "task_id": task_id, "runner_id": principal.runner_id,
            "grant_digest": grant_digest, "permit_consumed": True,
        }

    def submit_attestation(self, *, principal: RunnerIdentity, task_id: str,
                           lease_token: str, signed_attestation: dict[str, Any]) -> dict[str, Any]:
        self._scoped_task(principal, task_id)
        self._assert_receipt_key_binding(principal, signed_attestation)
        current = self.store.get_current_execution_token(
            task_id=task_id, tenant_id=principal.tenant_id, runner_id=principal.runner_id,
        )
        if not isinstance(lease_token, str) or lease_token != current["lease_token"]:
            raise PermissionError("receipt request does not carry this runner's current lease token")
        return self.store.record_runner_attestation(
            task_id=task_id, tenant_id=principal.tenant_id, lease_token=lease_token,
            signed_attestation=signed_attestation, verifier=self.attestation_verifier,
        )

    def reconcile_attestation(self, *, principal: RunnerIdentity, task_id: str,
                              signed_attestation: dict[str, Any]) -> dict[str, Any]:
        """Submit signed evidence for a journal-blocked expired lease; never claims or executes."""
        self._scoped_task(principal, task_id)
        self._assert_receipt_key_binding(principal, signed_attestation)
        return self.store.reconcile_late_runner_attestation(
            task_id=task_id, tenant_id=principal.tenant_id, runner_id=principal.runner_id,
            signed_attestation=signed_attestation, verifier=self.attestation_verifier,
        )

    @staticmethod
    def _assert_receipt_key_binding(principal: RunnerIdentity, envelope: Any) -> None:
        signature = envelope.get("signature") if isinstance(envelope, dict) else None
        if (not isinstance(signature, dict) or signature.get("algorithm") != "ed25519"
                or signature.get("key_id") != principal.runner_id):
            raise PermissionError("runner receipt signing key ID must match the authenticated runner identity")

    def _assert_lease_token(self, principal: RunnerIdentity, task_id: str, lease_token: str) -> None:
        lease = self.current_lease(principal=principal, task_id=task_id)
        if not isinstance(lease_token, str) or not lease_token or lease_token != lease["lease_token"]:
            raise PermissionError("request does not carry this runner's current lease token")

    def _scoped_task(self, principal: RunnerIdentity, task_id: str) -> dict[str, Any]:
        if not isinstance(principal, RunnerIdentity):
            raise PermissionError("runner identity must come from the authenticated TLS peer")
        task = self.store.get_task(task_id=task_id, tenant_id=principal.tenant_id)
        targets = task["target_ids"]
        if (not set(targets).issubset(principal.target_ids)
                or task["operation_id"] not in principal.operation_ids
                or task["environment"] not in principal.environments):
            raise PermissionError("task is outside the authenticated runner's registered scope")
        return task


def mtls_server_context(*, certificate: str, private_key: str, client_ca: str,
                        require_root_owned: bool = True) -> ssl.SSLContext:
    """Build a TLS 1.2+ server context that requires CA-verified client certificates."""
    cert_path = _checked_file(certificate, require_root_owned=require_root_owned)
    key_path = _checked_file(private_key, private=True, require_root_owned=require_root_owned)
    ca_path = _checked_file(client_ca, require_root_owned=require_root_owned)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    context.load_verify_locations(cafile=str(ca_path))
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PermissionError("worker API redirects are forbidden")


class MTLSWorkerClient:
    """Pinned-hostname mTLS client implementing lease and one-shot permit protocols."""

    _MAX_RESPONSE = 1024 * 1024

    def __init__(self, *, base_url: str, runner_id: str, client_certificate: str,
                 client_private_key: str, server_ca: str, timeout_seconds: int = 15) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("worker API URL must be a bare HTTPS origin without credentials or path")
        if not isinstance(runner_id, str) or not _SAFE_ID.fullmatch(runner_id):
            raise ValueError("runner_id must be specific and bounded")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            raise ValueError("worker API timeout must be between 1 and 30 seconds")
        self.base_url = f"https://{parsed.netloc}"
        self.runner_id = runner_id
        self.timeout_seconds = timeout_seconds
        key_path = _checked_file(client_private_key, private=True)
        cert_path = _checked_file(client_certificate)
        ca_path = _checked_file(server_ca)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context),
        )

    def get_current_execution_lease(self, *, task_id: str, runner_id: str) -> dict[str, Any]:
        self._assert_runner(runner_id)
        lease = self._request("GET", f"/v1/tasks/{_task_uuid(task_id)}/lease")
        if lease.get("runner_id") != self.runner_id:
            raise PermissionError("worker API lease identity does not match the client certificate")
        return lease

    def list_ready_tasks(self) -> list[dict[str, Any]]:
        result = self._request("GET", "/v1/tasks/ready")
        tasks = result.get("tasks")
        if not isinstance(tasks, list) or len(tasks) > 100:
            raise ConnectionError("worker API returned an invalid ready-task list")
        for task in tasks:
            if (not isinstance(task, dict) or not isinstance(task.get("task_id"), str)
                    or not isinstance(task.get("operation_id"), str)
                    or not isinstance(task.get("target_ids"), list)
                    or not isinstance(task.get("environment"), str)
                    or not isinstance(task.get("plan_digest"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", task["plan_digest"])):
                raise ConnectionError("worker API returned malformed ready-task metadata")
            _task_uuid(task["task_id"])
        return tasks

    def claim(self, *, task_id: str) -> dict[str, Any]:
        task_id = _task_uuid(task_id)
        result = self._request("POST", f"/v1/tasks/{task_id}/lease", {})
        generation = result.get("lease_generation")
        if (result.get("task_id") != task_id or result.get("runner_id") != self.runner_id
                or result.get("status") != "leased" or not isinstance(result.get("lease_token"), str)
                or not result["lease_token"] or isinstance(generation, bool)
                or not isinstance(generation, int) or generation < 1):
            raise ConnectionError("worker API returned an invalid or mis-scoped lease")
        return result

    def issue_grant(self, *, task_id: str, lease_token: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/tasks/{_task_uuid(task_id)}/grant", {
            "lease_token": _bounded_secret(lease_token, "lease_token"),
        })

    def consume_execution_permit(self, *, task_id: str, runner_id: str,
                                 grant_digest: str) -> dict[str, Any]:
        self._assert_runner(runner_id)
        if not isinstance(grant_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", grant_digest):
            raise ValueError("grant_digest must be a lowercase SHA-256 digest")
        lease = self.get_current_execution_lease(task_id=task_id, runner_id=runner_id)
        return self._request("POST", f"/v1/tasks/{_task_uuid(task_id)}/consume", {
            "lease_token": _bounded_secret(lease["lease_token"], "lease_token"),
            "grant_digest": grant_digest,
        })

    def submit_attestation(self, *, task_id: str, signed_attestation: dict[str, Any],
                           lease_token: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/tasks/{_task_uuid(task_id)}/attestation", {
            "lease_token": _bounded_secret(lease_token, "lease_token"),
            "signed_attestation": signed_attestation,
        })

    def reconcile_attestation(self, *, task_id: str,
                              signed_attestation: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/tasks/{_task_uuid(task_id)}/reconcile-attestation", {
            "signed_attestation": signed_attestation,
        })

    def _assert_runner(self, runner_id: str) -> None:
        if runner_id != self.runner_id:
            raise PermissionError("caller runner_id differs from the configured mTLS client identity")

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data is not None else {})},
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise ConnectionError("worker API returned an unexpected response")
                payload = response.read(self._MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                raise PermissionError("worker API redirects are forbidden") from None
            if exc.code == 403:
                raise PermissionError("worker API denied the authenticated operation") from None
            if exc.code == 404:
                raise KeyError("worker API task or lease was not found") from None
            raise ConnectionError(f"worker API request failed with HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError("mutually authenticated worker API is unavailable") from exc
        if len(payload) > self._MAX_RESPONSE:
            raise ConnectionError("worker API response exceeds 1 MiB")
        try:
            result = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ConnectionError("worker API returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ConnectionError("worker API response must be a JSON object")
        if "error" in result:
            raise PermissionError("worker API returned an error response")
        return result


def _checked_file(value: str, *, private: bool = False,
                  require_root_owned: bool = False):
    path = Path(value).expanduser()
    if path.is_symlink() or not path.is_absolute() or not path.is_file():
        raise PermissionError("mTLS certificate, key, and trust paths must be absolute regular files")
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022):
        raise PermissionError("mTLS private key must be owner-only; trust files must not be group/other writable")
    if private and hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        if not require_root_owned or info.st_uid != 0:
            raise PermissionError("mTLS private key owner does not match its service account")
    if require_root_owned and os.name == "posix" and info.st_uid != 0:
        raise PermissionError("server TLS trust material must be root-owned")
    return path


def _task_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("task_id must be a UUID") from exc


def _bounded_secret(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{field} must be a non-empty bounded string")
    return value


def build_mtls_worker_server(*, api: AuthenticatedWorkerAPI,
                             registry: RunnerCertificateRegistry,
                             tls_context: ssl.SSLContext,
                             address: tuple[str, int] = ("127.0.0.1", 9443)) -> ThreadingHTTPServer:
    """Build a small mTLS-only worker API; no endpoint accepts arbitrary commands.

    The supplied context must require client certificates. Loopback is the lab
    default. Remote regional runners should bind only to a private interface,
    enforce host firewall policy, and use a dedicated workload CA.
    """
    if api is None or registry is None or not isinstance(tls_context, ssl.SSLContext):
        raise ValueError("worker API, reviewed certificate registry, and TLS context are required")
    if tls_context.verify_mode != ssl.CERT_REQUIRED:
        raise PermissionError("worker HTTPS server must require mutual TLS client certificates")
    host, port = address
    if (not isinstance(host, str) or not host or isinstance(port, bool)
            or not isinstance(port, int) or not 0 <= port <= 65535):
        raise ValueError("worker API bind address is invalid")
    if host in {"0.0.0.0", "::"}:
        raise PermissionError("worker API must not bind to a wildcard interface")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "A2ZWorkerAPI"
        sys_version = ""
        max_body = 16 * 1024

        def log_message(self, format: str, *args: Any) -> None:
            # Default HTTP logging can include query/body fragments; emit no secrets.
            return

        def setup(self) -> None:
            self.request.settimeout(15)
            super().setup()

        def handle_expect_100(self) -> bool:
            self._respond(417, {"error": "expectation_not_supported"})
            return False

        def do_GET(self) -> None:
            if self.path == "/v1/tasks/ready":
                try:
                    principal = registry.resolve_peer_certificate(
                        self.connection.getpeercert(), self.connection.getpeercert(binary_form=True),
                    )
                    self._respond(200, api.ready_tasks(principal=principal))
                except (ValueError, PermissionError, KeyError) as exc:
                    self._handle_error(exc)
                except Exception:
                    self._respond(500, {"error": "worker_api_internal_error"})
                return
            route = re.fullmatch(r"/v1/tasks/([0-9a-fA-F-]{36})/lease", self.path)
            if not route:
                self._respond(404, {"error": "not_found"})
                return
            try:
                task_id = str(UUID(route.group(1)))
                principal = registry.resolve_peer_certificate(
                    self.connection.getpeercert(), self.connection.getpeercert(binary_form=True),
                )
                result = api.current_lease(principal=principal, task_id=task_id)
                self._respond(200, result)
            except (ValueError, PermissionError, KeyError) as exc:
                self._handle_error(exc)

        def do_POST(self) -> None:
            match = re.fullmatch(r"/v1/tasks/([0-9a-fA-F-]{36})/(lease|grant|consume|attestation|reconcile-attestation)", self.path)
            if not match:
                self._respond(404, {"error": "not_found"})
                return
            try:
                task_id = str(UUID(match.group(1)))
                principal = registry.resolve_peer_certificate(
                    self.connection.getpeercert(), self.connection.getpeercert(binary_form=True),
                )
                body = self._read_json()
                route = match.group(2)
                if route == "lease":
                    if body != {}:
                        raise ValueError("lease request body must be empty")
                    result = api.claim(principal=principal, task_id=task_id)
                elif route == "grant":
                    if set(body) != {"lease_token"}:
                        raise ValueError("grant request requires only lease_token")
                    result = api.issue_grant(
                        principal=principal, task_id=task_id, lease_token=body["lease_token"],
                    )
                elif route == "consume":
                    if set(body) != {"lease_token", "grant_digest"}:
                        raise ValueError("consume request requires lease_token and grant_digest")
                    result = api.consume_permit(
                        principal=principal, task_id=task_id,
                        lease_token=body["lease_token"], grant_digest=body["grant_digest"],
                    )
                elif route == "attestation":
                    if set(body) != {"lease_token", "signed_attestation"} or not isinstance(body["signed_attestation"], dict):
                        raise ValueError("attestation request requires lease_token and signed_attestation")
                    result = api.submit_attestation(
                        principal=principal, task_id=task_id,
                        lease_token=body["lease_token"], signed_attestation=body["signed_attestation"],
                    )
                else:
                    if set(body) != {"signed_attestation"} or not isinstance(body["signed_attestation"], dict):
                        raise ValueError("reconciliation request requires only signed_attestation")
                    result = api.reconcile_attestation(
                        principal=principal, task_id=task_id,
                        signed_attestation=body["signed_attestation"],
                    )
                self._respond(200, result)
            except (ValueError, PermissionError, KeyError) as exc:
                self._handle_error(exc)
            except Exception:
                self._respond(500, {"error": "worker_api_internal_error"})

        def _read_json(self) -> dict[str, Any]:
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("transfer-encoded request bodies are unsupported")
            length_text = self.headers.get("Content-Length")
            if not isinstance(length_text, str) or not length_text.isdigit():
                raise ValueError("a bounded Content-Length is required")
            length = int(length_text)
            if length > self.max_body:
                raise ValueError("worker request body exceeds 16 KiB")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("worker API requires application/json")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("worker request body is truncated")
            try:
                body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                  parse_constant=_reject_constant)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValueError("worker request JSON is invalid") from exc
            if not isinstance(body, dict):
                raise ValueError("worker request body must be a JSON object")
            return body

        def _handle_error(self, exc: Exception) -> None:
            if isinstance(exc, KeyError):
                self._respond(404, {"error": "task_not_found"})
            elif isinstance(exc, PermissionError):
                self._respond(403, {"error": str(exc)[:256]})
            else:
                self._respond(400, {"error": str(exc)[:256]})

        def _respond(self, status: int, body: dict[str, Any]) -> None:
            payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

    class TLSWorkerServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False

        def __init__(self) -> None:
            super().__init__(address, Handler, bind_and_activate=True)
            self.socket = tls_context.wrap_socket(self.socket, server_side=True)

    return TLSWorkerServer()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker API JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
