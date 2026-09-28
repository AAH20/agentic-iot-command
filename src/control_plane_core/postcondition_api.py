from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from uuid import UUID

from .worker_api import _NoRedirect, _checked_file, _reject_constant, _unique_pairs


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


@dataclass(frozen=True)
class PostconditionVerifierIdentity:
    """Server-owned scope derived from a verifier's mutually authenticated TLS certificate."""

    spiffe_id: str
    verifier_id: str
    tenant_id: str
    certificate_sha256: str
    target_ids: frozenset[str]
    operation_ids: frozenset[str]
    environments: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.spiffe_id, str) or not self.spiffe_id.startswith("spiffe://"):
            raise ValueError("postcondition verifier identity must have a SPIFFE URI")
        if any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value)
               for value in (self.verifier_id, self.tenant_id)):
            raise ValueError("postcondition verifier and tenant IDs must be exact bounded identifiers")
        if not isinstance(self.certificate_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.certificate_sha256):
            raise ValueError("postcondition verifier identity must pin a TLS certificate fingerprint")
        for field, values in (("target_ids", self.target_ids), ("operation_ids", self.operation_ids),
                              ("environments", self.environments)):
            if (not isinstance(values, frozenset) or not values or len(values) > 500
                    or any(not isinstance(value, str) or not value.strip() or value == "*" or len(value) > 512
                           for value in values)):
                raise ValueError(f"{field} must be a non-empty exact allowlist")
        if not self.environments.issubset({"lab", "development", "staging"}):
            raise PermissionError("postcondition verifier cannot be enrolled for production environments")


class PostconditionVerifierCertificateRegistry:
    """Maps exactly one TLS URI SAN and certificate fingerprint to a verifier scope."""

    def __init__(self, identities: Mapping[str, PostconditionVerifierIdentity]) -> None:
        if not identities:
            raise ValueError("at least one reviewed postcondition verifier identity is required")
        self._identities = dict(identities)
        for spiffe_id, identity in self._identities.items():
            if not isinstance(identity, PostconditionVerifierIdentity) or spiffe_id != identity.spiffe_id:
                raise ValueError("verifier registry keys must match their configured SPIFFE IDs")

    def resolve_peer_certificate(self, certificate: Mapping[str, Any] | None,
                                 certificate_der: bytes | None) -> PostconditionVerifierIdentity:
        if not isinstance(certificate, Mapping) or not isinstance(certificate_der, bytes) or not certificate_der:
            raise PermissionError("mutually authenticated postcondition verifier certificate is required")
        sans = certificate.get("subjectAltName")
        if not isinstance(sans, (tuple, list)):
            raise PermissionError("postcondition verifier certificate has no subject alternative names")
        uris = [value for kind, value in sans if kind == "URI"]
        if len(uris) != 1 or not isinstance(uris[0], str):
            raise PermissionError("postcondition verifier certificate must contain exactly one URI identity")
        identity = self._identities.get(uris[0])
        if identity is None:
            raise PermissionError("postcondition verifier certificate identity is not enrolled")
        if hashlib.sha256(certificate_der).hexdigest() != identity.certificate_sha256:
            raise PermissionError("postcondition verifier certificate fingerprint has been revoked or rotated")
        return identity


class AuthenticatedPostconditionAPI:
    """Expose only scoped candidate reads and signed postcondition submissions."""

    def __init__(self, *, store: Any, verifier: Any) -> None:
        if store is None or verifier is None:
            raise PermissionError("postcondition API requires a journal and trusted signature verifier")
        self.store = store
        self.verifier = verifier

    def get_candidate(self, *, principal: PostconditionVerifierIdentity, task_id: str) -> dict[str, Any]:
        if not isinstance(principal, PostconditionVerifierIdentity):
            raise PermissionError("postcondition identity must come from the authenticated TLS peer")
        candidate = self.store.get_postcondition_candidate(task_id=_task_uuid(task_id), tenant_id=principal.tenant_id)
        self._scope_candidate(principal, candidate)
        return candidate

    def list_candidates(self, *, principal: PostconditionVerifierIdentity, limit: int = 20) -> dict[str, Any]:
        if not isinstance(principal, PostconditionVerifierIdentity):
            raise PermissionError("postcondition identity must come from the authenticated TLS peer")
        candidates = self.store.list_postcondition_candidates(
            tenant_id=principal.tenant_id, target_ids=principal.target_ids,
            operation_ids=principal.operation_ids, environments=principal.environments,
            limit=limit,
        )
        for candidate in candidates:
            self._scope_candidate(principal, candidate)
        return {"tasks": candidates}

    def submit_attestation(self, *, principal: PostconditionVerifierIdentity, task_id: str,
                           signed_attestation: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(principal, PostconditionVerifierIdentity):
            raise PermissionError("postcondition identity must come from the authenticated TLS peer")
        task_id = _task_uuid(task_id)
        if not isinstance(signed_attestation, dict) or not isinstance(signed_attestation.get("attestation"), dict):
            raise ValueError("signed postcondition envelope is required")
        body = signed_attestation["attestation"]
        if body.get("task_id") != task_id or body.get("tenant_id") != principal.tenant_id:
            raise PermissionError("postcondition envelope task or tenant differs from authenticated identity")
        if body.get("verifier_id") != principal.verifier_id:
            raise PermissionError("postcondition envelope signer differs from authenticated verifier identity")
        if (body.get("target_id") not in principal.target_ids
                or body.get("operation_id") not in principal.operation_ids
                or body.get("environment") not in principal.environments):
            raise PermissionError("postcondition envelope is outside the authenticated verifier scope")
        result = self.store.record_postcondition_attestation(
            task_id=task_id, tenant_id=principal.tenant_id,
            signed_attestation=signed_attestation, verifier=self.verifier,
        )
        if result.get("task_id") != task_id:
            raise PermissionError("journal returned a postcondition result outside the requested task")
        return result

    @staticmethod
    def _scope_candidate(principal: PostconditionVerifierIdentity, candidate: Any) -> None:
        if not isinstance(candidate, dict) or candidate.get("tenant_id") != principal.tenant_id:
            raise PermissionError("journal returned a candidate outside authenticated tenant scope")
        if (candidate.get("target_id") not in principal.target_ids
                or candidate.get("operation_id") not in principal.operation_ids
                or candidate.get("environment") not in principal.environments):
            raise PermissionError("journal candidate is outside the authenticated verifier scope")


def build_mtls_postcondition_server(*, api: AuthenticatedPostconditionAPI,
                                    registry: PostconditionVerifierCertificateRegistry,
                                    tls_context: ssl.SSLContext,
                                    address: tuple[str, int] = ("127.0.0.1", 9444)) -> ThreadingHTTPServer:
    """Build the verifier-only mTLS API; it has no runner, approval, or command route."""
    if api is None or registry is None or not isinstance(tls_context, ssl.SSLContext):
        raise ValueError("postcondition API, verifier registry, and TLS context are required")
    if tls_context.verify_mode != ssl.CERT_REQUIRED:
        raise PermissionError("postcondition HTTPS server must require mutual TLS client certificates")
    host, port = address
    if (not isinstance(host, str) or not host or isinstance(port, bool)
            or not isinstance(port, int) or not 0 <= port <= 65535):
        raise ValueError("postcondition API bind address is invalid")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("postcondition API bind address must be a numeric IP") from exc
    if not ip.is_loopback:
        raise PermissionError("postcondition API must bind only to a loopback interface")
    selected_address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "A2ZPostconditionAPI"
        sys_version = ""
        max_body = 64 * 1024

        def log_message(self, format: str, *args: Any) -> None:
            return

        def setup(self) -> None:
            self.request.settimeout(15)
            super().setup()

        def handle_expect_100(self) -> bool:
            self._respond(417, {"error": "expectation_not_supported"})
            return False

        def do_GET(self) -> None:
            if self.path == "/v1/postconditions/ready":
                try:
                    self._respond(200, api.list_candidates(principal=self._principal()))
                except (ValueError, PermissionError, KeyError) as exc:
                    self._handle_error(exc)
                except Exception:
                    self._respond(500, {"error": "postcondition_api_internal_error"})
                return
            match = re.fullmatch(r"/v1/postconditions/([0-9a-fA-F-]{36})", self.path)
            if not match:
                self._respond(404, {"error": "not_found"})
                return
            try:
                principal = self._principal()
                result = api.get_candidate(principal=principal, task_id=_task_uuid(match.group(1)))
                self._respond(200, result)
            except (ValueError, PermissionError, KeyError) as exc:
                self._handle_error(exc)
            except Exception:
                self._respond(500, {"error": "postcondition_api_internal_error"})

        def do_POST(self) -> None:
            match = re.fullmatch(r"/v1/postconditions/([0-9a-fA-F-]{36})/attestation", self.path)
            if not match:
                self._respond(404, {"error": "not_found"})
                return
            try:
                body = self._read_json()
                if set(body) != {"signed_attestation"} or not isinstance(body["signed_attestation"], dict):
                    raise ValueError("request requires only signed_attestation")
                result = api.submit_attestation(
                    principal=self._principal(), task_id=_task_uuid(match.group(1)),
                    signed_attestation=body["signed_attestation"],
                )
                self._respond(200, result)
            except (ValueError, PermissionError, KeyError) as exc:
                self._handle_error(exc)
            except Exception:
                self._respond(500, {"error": "postcondition_api_internal_error"})

        def _principal(self) -> PostconditionVerifierIdentity:
            return registry.resolve_peer_certificate(
                self.connection.getpeercert(), self.connection.getpeercert(binary_form=True),
            )

        def _read_json(self) -> dict[str, Any]:
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("transfer-encoded request bodies are unsupported")
            length_text = self.headers.get("Content-Length")
            if not isinstance(length_text, str) or not length_text.isdigit():
                raise ValueError("a bounded Content-Length is required")
            length = int(length_text)
            if length > self.max_body:
                raise ValueError("postcondition request body exceeds 64 KiB")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("postcondition API requires application/json")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("postcondition request body is truncated")
            try:
                body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                  parse_constant=_reject_constant)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValueError("postcondition request JSON is invalid") from exc
            if not isinstance(body, dict):
                raise ValueError("postcondition request body must be a JSON object")
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

    class TLSPostconditionServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False
        address_family = selected_address_family

        def __init__(self) -> None:
            super().__init__(address, Handler, bind_and_activate=True)
            self.socket = tls_context.wrap_socket(self.socket, server_side=True)

    return TLSPostconditionServer()


class MTLSPostconditionClient:
    """Pinned-hostname mTLS client for the observer's two-route journal interface."""

    _MAX_RESPONSE = 1024 * 1024

    def __init__(self, *, base_url: str, verifier_id: str, tenant_id: str,
                 client_certificate: str, client_private_key: str, server_ca: str,
                 timeout_seconds: int = 15) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("postcondition API URL must be a bare HTTPS origin without credentials or path")
        if any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value)
               for value in (verifier_id, tenant_id)):
            raise ValueError("postcondition verifier and tenant IDs must be exact bounded identifiers")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            raise ValueError("postcondition API timeout must be between 1 and 30 seconds")
        key_path = _checked_file(client_private_key, private=True)
        cert_path = _checked_file(client_certificate)
        ca_path = _checked_file(server_ca)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.base_url = f"https://{parsed.netloc}"
        self.verifier_id = verifier_id
        self.tenant_id = tenant_id
        self.timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context),
        )

    def get_postcondition_candidate(self, *, task_id: str, tenant_id: str) -> dict[str, Any]:
        if tenant_id != self.tenant_id:
            raise PermissionError("requested tenant differs from configured verifier identity")
        task_id = _task_uuid(task_id)
        result = self._request("GET", f"/v1/postconditions/{task_id}")
        if result.get("task_id") != task_id or result.get("tenant_id") != self.tenant_id:
            raise PermissionError("postcondition API returned a candidate outside configured identity scope")
        return result

    def list_postcondition_candidates(self, *, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("postcondition candidate page size must be between 1 and 100")
        result = self._request("GET", "/v1/postconditions/ready")
        tasks = result.get("tasks")
        if not isinstance(tasks, list) or len(tasks) > limit:
            raise ConnectionError("postcondition API returned an invalid candidate list")
        for task in tasks:
            if (not isinstance(task, dict) or not isinstance(task.get("task_id"), str)
                    or task.get("tenant_id") != self.tenant_id
                    or not isinstance(task.get("target_id"), str)
                    or not isinstance(task.get("operation_id"), str)
                    or not isinstance(task.get("environment"), str)
                    or not isinstance(task.get("plan_digest"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", task["plan_digest"])):
                raise ConnectionError("postcondition API returned malformed candidate metadata")
            if _task_uuid(task["task_id"]) != task["task_id"]:
                raise ConnectionError("postcondition API returned a non-canonical task UUID")
        return tasks

    def record_postcondition_attestation(self, *, task_id: str, tenant_id: str,
                                         signed_attestation: dict[str, Any]) -> dict[str, Any]:
        if tenant_id != self.tenant_id:
            raise PermissionError("requested tenant differs from configured verifier identity")
        task_id = _task_uuid(task_id)
        body = signed_attestation.get("attestation") if isinstance(signed_attestation, dict) else None
        if (not isinstance(body, dict) or body.get("task_id") != task_id
                or body.get("tenant_id") != self.tenant_id or body.get("verifier_id") != self.verifier_id):
            raise PermissionError("signed postcondition evidence differs from configured verifier identity")
        result = self._request("POST", f"/v1/postconditions/{task_id}/attestation", {
            "signed_attestation": signed_attestation,
        })
        if result.get("task_id") != task_id:
            raise PermissionError("postcondition API returned a result outside the requested task")
        return result

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
                    raise ConnectionError("postcondition API returned an unexpected response")
                payload = response.read(self._MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                raise PermissionError("postcondition API redirects are forbidden") from None
            if exc.code == 403:
                raise PermissionError("postcondition API denied the authenticated operation") from None
            if exc.code == 404:
                raise KeyError("postcondition task was not found") from None
            raise ConnectionError(f"postcondition API request failed with HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError("mutually authenticated postcondition API is unavailable") from exc
        if len(payload) > self._MAX_RESPONSE:
            raise ConnectionError("postcondition API response exceeds 1 MiB")
        try:
            result = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ConnectionError("postcondition API returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ConnectionError("postcondition API response must be a JSON object")
        if "error" in result:
            raise PermissionError("postcondition API returned an error response")
        return result


def _task_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("task_id must be a UUID") from exc
