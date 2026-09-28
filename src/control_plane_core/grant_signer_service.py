from __future__ import annotations

import json
import os
import re
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from .execution_grants import Ed25519ExecutionGrantSigner, _timestamp


MAX_MESSAGE_BYTES = 40 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


@dataclass(frozen=True)
class GrantSigningPolicy:
    """Exact scope enforced at the key-holding boundary for a lab signer."""

    api_uid: int
    tenant_id: str
    runner_id: str
    target_ids: frozenset[str]
    operation_ids: frozenset[str]
    max_runtime_seconds: int = 120

    def __post_init__(self) -> None:
        if isinstance(self.api_uid, bool) or not isinstance(self.api_uid, int) or self.api_uid < 1:
            raise ValueError("grant signer API uid must be a non-root numeric uid")
        for name, value in (("tenant_id", self.tenant_id), ("runner_id", self.runner_id)):
            if not isinstance(value, str) or not _SCOPE_ID.fullmatch(value):
                raise ValueError(f"grant signer {name} must be an exact bounded identifier")
        if (not isinstance(self.target_ids, frozenset) or len(self.target_ids) != 1
                or any(not isinstance(value, str) or not _SCOPE_ID.fullmatch(value) for value in self.target_ids)):
            raise ValueError("initial grant signer policy must pin exactly one target")
        if (not isinstance(self.operation_ids, frozenset) or len(self.operation_ids) != 1
                or any(not isinstance(value, str) or not _SCOPE_ID.fullmatch(value) for value in self.operation_ids)):
            raise ValueError("initial grant signer policy must pin exactly one operation")
        if (isinstance(self.max_runtime_seconds, bool) or not isinstance(self.max_runtime_seconds, int)
                or not 1 <= self.max_runtime_seconds <= 300):
            raise ValueError("grant signer runtime ceiling must be from 1 to 300 seconds")

    def authorize(self, grant: Any) -> None:
        if not isinstance(grant, dict):
            raise ValueError("grant signer request must contain an object")
        expected_fields = {
            "schema_version", "grant_id", "task_id", "tenant_id", "target_id", "operation_id",
            "environment", "plan_digest", "authorization_mode", "authorization_id", "approval_id",
            "policy_digest", "impact_assessment_digest", "lease_generation", "runner_id",
            "lease_token_sha256", "issued_at", "expires_at", "max_runtime_seconds",
        }
        if set(grant) != expected_fields:
            raise ValueError("grant fields do not match the signer protocol")
        exact = {
            "schema_version": "a2z-execution-grant-v2", "tenant_id": self.tenant_id,
            "runner_id": self.runner_id, "environment": "lab",
        }
        for name, value in exact.items():
            if grant.get(name) != value:
                raise PermissionError(f"grant signer rejected {name} outside its pinned scope")
        if grant.get("target_id") not in self.target_ids or grant.get("operation_id") not in self.operation_ids:
            raise PermissionError("grant signer rejected target or operation outside its pinned scope")
        for name in ("grant_id", "task_id", "authorization_id"):
            if not isinstance(grant.get(name), str):
                raise ValueError(f"grant signer {name} must be a UUID")
            try:
                UUID(grant[name])
            except ValueError as exc:
                raise ValueError(f"grant signer {name} must be a UUID") from exc
        for name in ("plan_digest", "lease_token_sha256"):
            if not isinstance(grant.get(name), str) or not _DIGEST.fullmatch(grant[name]):
                raise ValueError(f"grant signer {name} must be a SHA-256 digest")
        generation = grant.get("lease_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise ValueError("grant signer lease_generation must be positive")
        runtime = grant.get("max_runtime_seconds")
        if isinstance(runtime, bool) or not isinstance(runtime, int) or not 1 <= runtime <= self.max_runtime_seconds:
            raise PermissionError("grant signer runtime exceeds its pinned limit")
        mode = grant.get("authorization_mode")
        if mode == "operator_approval":
            if (grant.get("approval_id") != grant.get("authorization_id")
                    or grant.get("policy_digest") is not None
                    or grant.get("impact_assessment_digest") is not None):
                raise PermissionError("operator approval claims are inconsistent")
        elif mode == "standing_policy":
            if grant.get("approval_id") is not None:
                raise PermissionError("standing-policy grant cannot claim operator approval")
            if any(not isinstance(grant.get(name), str) or not _DIGEST.fullmatch(grant[name])
                   for name in ("policy_digest", "impact_assessment_digest")):
                raise PermissionError("standing-policy grant requires signed evidence digests")
        else:
            raise PermissionError("grant signer authorization mode is unsupported")
        issued = _timestamp(grant.get("issued_at"), "issued_at")
        expires = _timestamp(grant.get("expires_at"), "expires_at")
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        if (issued > now + timedelta(seconds=15) or expires <= now or expires <= issued
                or expires - issued > timedelta(seconds=min(runtime, self.max_runtime_seconds))):
            raise PermissionError("grant signer rejected expired or overlong grant")


class UnixExecutionGrantSigner:
    """Client for a systemd-activated local signing service; never carries key material."""

    def __init__(self, socket_path: str | Path, *, expected_signer_uid: int,
                 key_id: str, timeout_seconds: float = 3.0) -> None:
        self.socket_path = Path(socket_path)
        if isinstance(expected_signer_uid, bool) or not isinstance(expected_signer_uid, int) or expected_signer_uid < 1:
            raise ValueError("expected signer uid must be a non-root numeric uid")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("expected grant-signing key ID is invalid")
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("signer socket timeout must be from 0.1 to 10 seconds")
        self.expected_signer_uid = expected_signer_uid
        self.key_id = key_id
        self.timeout_seconds = timeout_seconds

    def sign(self, grant: dict[str, Any]) -> dict[str, Any]:
        if self.socket_path.is_symlink():
            raise PermissionError("grant signer socket path must not be a symlink")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout_seconds)
        try:
            client.connect(str(self.socket_path))
            _assert_peer_uid(client, self.expected_signer_uid)
            client.sendall(json.dumps({"grant": grant}, sort_keys=True, separators=(",", ":"),
                                      allow_nan=False).encode("utf-8") + b"\n")
            client.shutdown(socket.SHUT_WR)
            raw = _read_bounded(client, MAX_MESSAGE_BYTES)
        except (OSError, ValueError) as exc:
            raise PermissionError("confined execution-grant signer is unavailable or rejected the request") from exc
        finally:
            client.close()
        try:
            response = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PermissionError("grant signer returned malformed JSON") from exc
        if not isinstance(response, dict) or set(response) != {"envelope"}:
            raise PermissionError("grant signer returned an error or invalid response")
        envelope = response["envelope"]
        if (not isinstance(envelope, dict) or set(envelope) != {"grant", "signature"}
                or envelope.get("grant") != grant or not isinstance(envelope.get("signature"), dict)
                or envelope["signature"].get("key_id") != self.key_id):
            raise PermissionError("grant signer response does not match the requested grant or pinned key")
        return envelope


def serve_signing_connection(connection: socket.socket, *, api_uid: int,
                             policy: GrantSigningPolicy,
                             signer: Ed25519ExecutionGrantSigner) -> None:
    """Handle one request from the authenticated local API process."""
    try:
        _assert_peer_uid(connection, api_uid)
        raw = _read_line_bounded(connection, MAX_MESSAGE_BYTES)
        request = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(request, dict) or set(request) != {"grant"}:
            raise ValueError("request must contain only grant")
        policy.authorize(request["grant"])
        envelope = signer.sign(request["grant"])
        response = {"envelope": envelope}
    except Exception:
        response = {"error": "grant_signing_denied"}
    try:
        connection.sendall(json.dumps(response, sort_keys=True, separators=(",", ":"),
                                      allow_nan=False).encode("utf-8") + b"\n")
    except OSError:
        pass


def _assert_peer_uid(connection: socket.socket, expected_uid: int) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        raise PermissionError("Linux Unix-socket peer credential verification is unavailable")
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    if uid != expected_uid:
        raise PermissionError("Unix-socket peer uid is not authorized")


def _read_bounded(connection: socket.socket, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = connection.recv(min(4096, limit + 1 - size))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ValueError("signer response exceeds size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_line_bounded(connection: socket.socket, limit: int) -> bytes:
    chunks = bytearray()
    while len(chunks) <= limit:
        chunk = connection.recv(min(4096, limit + 1 - len(chunks)))
        if not chunk:
            break
        newline = chunk.find(b"\n")
        if newline >= 0:
            chunks.extend(chunk[:newline])
            if chunk[newline + 1:].strip():
                raise ValueError("trailing signer request data is not allowed")
            return bytes(chunks)
        chunks.extend(chunk)
    raise ValueError("signer request is incomplete or exceeds size limit")


def load_signing_service(config_path: str | Path) -> tuple[GrantSigningPolicy, Ed25519ExecutionGrantSigner, str]:
    """Load a root-managed config and a key readable only by this non-root service UID."""
    if os.geteuid() == 0:
        raise PermissionError("grant signer service must run as its dedicated non-root identity")
    path = Path(config_path)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("grant signer configuration must be a regular non-symlink file")
    info = path.stat()
    if (info.st_uid != 0 or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o640):
        raise PermissionError("grant signer configuration must be root:signer-group mode 0640")
    config_parent = path.parent
    parent_info = config_parent.stat()
    if (config_parent.is_symlink() or parent_info.st_uid != 0 or parent_info.st_gid != os.getegid()
            or stat.S_IMODE(parent_info.st_mode) != 0o750):
        raise PermissionError("grant signer configuration directory must be root:signer-group mode 0750")
    raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
                     parse_constant=_reject_constant)
    expected = {"schema_version", "socket_path", "private_key", "key_id", "api_uid", "tenant_id",
                "runner_id", "target_ids", "operation_ids", "max_runtime_seconds"}
    if not isinstance(raw, dict) or set(raw) != expected or raw.get("schema_version") != "a2z-grant-signer-config-v1":
        raise ValueError("grant signer config does not match the strict v1 contract")
    if not isinstance(raw["target_ids"], list) or not isinstance(raw["operation_ids"], list):
        raise ValueError("grant signer scopes must be JSON arrays")
    if (len(raw["target_ids"]) != 1 or len(raw["operation_ids"]) != 1
            or len(set(raw["target_ids"])) != 1 or len(set(raw["operation_ids"])) != 1):
        raise ValueError("grant signer config must pin exactly one unique target and operation")
    if (raw["socket_path"] != "/run/a2z-grant-signer/issuer.sock"
            or raw["private_key"] != "/etc/a2z-grant-signer/keys/issuer.pem"):
        raise ValueError("grant signer config paths differ from the hardened service contract")
    policy = GrantSigningPolicy(
        api_uid=raw["api_uid"], tenant_id=raw["tenant_id"], runner_id=raw["runner_id"],
        target_ids=frozenset(raw["target_ids"]), operation_ids=frozenset(raw["operation_ids"]),
        max_runtime_seconds=raw["max_runtime_seconds"],
    )
    if policy.api_uid == os.geteuid():
        raise PermissionError("grant signer and API must use distinct operating-system identities")
    key_path = Path(raw["private_key"])
    if key_path.is_symlink() or not key_path.is_file():
        raise PermissionError("grant signing key must be a regular non-symlink file")
    key_info = key_path.stat()
    if (key_info.st_uid != os.geteuid() or key_info.st_gid != os.getegid()
            or stat.S_IMODE(key_info.st_mode) != 0o400):
        raise PermissionError("grant signing key must be signer-owned mode 0400")
    parent = key_path.parent
    parent_info = parent.stat()
    if (parent.is_symlink() or parent_info.st_uid != 0 or parent_info.st_gid != os.getegid()
            or stat.S_IMODE(parent_info.st_mode) != 0o710):
        raise PermissionError("grant signing key directory must be root:signer-group mode 0710")
    signer = Ed25519ExecutionGrantSigner(key_path, key_id=raw["key_id"], require_root_owned_key=False)
    return policy, signer, raw["socket_path"]
