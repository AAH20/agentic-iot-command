from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .approval import Ed25519ApprovalVerifier
from .autonomy_profiles import Ed25519AutonomyProfileVerifier
from .execution_controls import RootManagedExecutionControl
from .execution_grants import Ed25519ExecutionGrantVerifier
from .goals import DurableGoalStore
from .grant_signer_service import UnixExecutionGrantSigner
from .impact_assessments import ImpactAssessmentVerifier
from .runner_attestations import Ed25519RunnerAttestationVerifier
from .worker_api import AuthenticatedWorkerAPI, build_mtls_worker_server, mtls_server_context
from .worker_api_registry import load_runner_certificate_registry


_CONFIG_FIELDS = {
    "schema_version", "database_path", "runner_registry_path", "approval_trust_directory",
    "runner_trust_directory", "grant_trust_directory", "autonomy_trust_directory",
    "impact_trust_directory", "execution_control_path", "signer_socket_path",
    "signer_uid", "signer_key_id", "tls_certificate", "tls_private_key", "client_ca",
    "bind_address", "port",
}
_PATH_FIELDS = _CONFIG_FIELDS - {"schema_version", "signer_uid", "signer_key_id", "bind_address", "port"}
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CONTROL_FIELDS = {"schema_version", "execution_enabled", "issued_at", "expires_at", "reason"}
_PINNED_PATHS = {
    "database_path": "/var/lib/a2z-control-plane/goals.sqlite3",
    "runner_registry_path": "/etc/a2z-control-plane/runner-identities.json",
    "approval_trust_directory": "/etc/a2z-control-plane/approval-trust",
    "runner_trust_directory": "/etc/a2z-control-plane/runner-trust",
    "grant_trust_directory": "/etc/a2z-control-plane/execution-grant-trust",
    "autonomy_trust_directory": "/etc/a2z-control-plane/autonomy-profile-trust",
    "impact_trust_directory": "/etc/a2z-control-plane/impact-assessment-trust",
    "execution_control_path": "/etc/a2z-control-plane/execution-control.json",
    "signer_socket_path": "/run/a2z-grant-signer/issuer.sock",
    "tls_certificate": "/etc/a2z-control-plane/worker-tls/worker-api.crt",
    "tls_private_key": "/etc/a2z-control-plane/worker-tls/worker-api.key",
    "client_ca": "/etc/a2z-control-plane/worker-tls/runner-client-ca.crt",
}


def load_worker_api_config(path: str | Path, *, require_root_owned: bool = True) -> dict[str, Any]:
    config_path = Path(path)
    _check_root_managed_file(config_path, "worker API config", require_root_owned=require_root_owned)
    raw_bytes = config_path.read_bytes()
    if len(raw_bytes) > 64 * 1024:
        raise ValueError("worker API config exceeds 64 KiB")
    config = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_unique_pairs,
                        parse_constant=_reject_constant)
    if not isinstance(config, dict) or set(config) != _CONFIG_FIELDS:
        raise ValueError("worker API config fields do not match the v1 contract")
    if config["schema_version"] != "a2z-worker-api-config-v1":
        raise ValueError("unsupported worker API config version")
    for field in _PATH_FIELDS:
        value = config[field]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError(f"{field} must be an absolute path")
        if value != _PINNED_PATHS[field]:
            raise PermissionError(f"{field} differs from the reviewed worker API v1 path")
    if (isinstance(config["signer_uid"], bool) or not isinstance(config["signer_uid"], int)
            or config["signer_uid"] < 1 or config["signer_uid"] == os.geteuid()):
        raise PermissionError("worker API and grant signer must have distinct non-root identities")
    if not isinstance(config["signer_key_id"], str) or not _KEY_ID.fullmatch(config["signer_key_id"]):
        raise ValueError("signer_key_id must be an exact Ed25519 key ID")
    bind = config["bind_address"]
    if not isinstance(bind, str):
        raise ValueError("worker API bind_address must be a loopback IP")
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise ValueError("worker API bind_address must be a numeric IP") from exc
    if str(address) != "127.0.0.1":
        raise PermissionError("worker API v1 binds only to 127.0.0.1")
    port = config["port"]
    if isinstance(port, bool) or not isinstance(port, int) or port != 9443:
        raise ValueError("worker API v1 uses only port 9443")
    config["database_path"] = str(_check_database_path(
        Path(config["database_path"]), require_service_owner=require_root_owned,
    ))
    return config


def build_worker_api_service(config_path: str | Path, *, require_root_owned: bool = True):
    _require_unprivileged_service_account(require_root_owned)
    config, registry, dependencies, tls_context = _load_runtime_settings(
        config_path, require_root_owned=require_root_owned,
    )
    store = DurableGoalStore(config["database_path"])
    api = AuthenticatedWorkerAPI(store=store, **dependencies)
    try:
        server = build_mtls_worker_server(
            api=api, registry=registry, tls_context=tls_context,
            address=(config["bind_address"], config["port"]),
        )
    except Exception:
        store.close()
        raise
    return server, store


def validate_worker_api_configuration(config_path: str | Path, *, require_root_owned: bool = True) -> None:
    """Validate all identities, keys, grants, and disabled execution gate without binding or opening SQLite."""
    _require_unprivileged_service_account(require_root_owned)
    _load_runtime_settings(config_path, require_root_owned=require_root_owned)


def _load_runtime_settings(config_path: str | Path, *, require_root_owned: bool):
    config = load_worker_api_config(config_path, require_root_owned=require_root_owned)
    registry = load_runner_certificate_registry(
        config["runner_registry_path"], require_root_owned=require_root_owned,
    )
    runner_ids = frozenset(identity.runner_id for identity in registry._identities.values())
    _validate_trust_directory(config["approval_trust_directory"], require_root_owned=require_root_owned)
    _validate_trust_directory(config["runner_trust_directory"], required_names={f"{item}.pem" for item in runner_ids},
                              require_root_owned=require_root_owned)
    _validate_trust_directory(config["grant_trust_directory"], required_names={f"{config['signer_key_id']}.pem"},
                              require_root_owned=require_root_owned)
    _validate_trust_directory(config["autonomy_trust_directory"], allow_empty=True,
                              require_root_owned=require_root_owned)
    _validate_trust_directory(config["impact_trust_directory"], allow_empty=True,
                              require_root_owned=require_root_owned)
    _validate_disabled_execution_control(config["execution_control_path"], require_root_owned=require_root_owned)
    _check_root_managed_file(Path(config["tls_certificate"]), "worker TLS certificate",
                             require_root_owned=require_root_owned)
    _check_root_managed_file(Path(config["client_ca"]), "worker client CA",
                             require_root_owned=require_root_owned)
    _check_service_private_key(Path(config["tls_private_key"]), require_root_owned=require_root_owned)
    tls_context = mtls_server_context(
        certificate=config["tls_certificate"], private_key=config["tls_private_key"],
        client_ca=config["client_ca"], require_root_owned=False,
    )
    dependencies = {
        "approval_verifier": Ed25519ApprovalVerifier(
            verifier_bin=str(Path(__file__).resolve().parents[2] / "scripts" / "verify-approval.sh"),
            trust_dir=config["approval_trust_directory"],
        ),
        "autonomy_profile_verifier": Ed25519AutonomyProfileVerifier(
            config["autonomy_trust_directory"], require_root_owned_trust=require_root_owned,
        ),
        "impact_verifier": ImpactAssessmentVerifier(
            config["impact_trust_directory"], require_root_owned_trust=require_root_owned,
        ),
        "grant_signer": UnixExecutionGrantSigner(
            config["signer_socket_path"], expected_signer_uid=config["signer_uid"],
            key_id=config["signer_key_id"],
        ),
        "grant_verifier": Ed25519ExecutionGrantVerifier(
            config["grant_trust_directory"], require_root_owned_trust=require_root_owned,
        ),
        "attestation_verifier": Ed25519RunnerAttestationVerifier(
            config["runner_trust_directory"], require_root_owned_trust=require_root_owned,
        ),
        "execution_control": RootManagedExecutionControl(
            config["execution_control_path"], require_root_owned=require_root_owned,
        ),
    }
    return config, registry, dependencies, tls_context


def _require_unprivileged_service_account(require_root_owned: bool) -> None:
    if require_root_owned and os.name == "posix" and os.geteuid() == 0:
        raise PermissionError("worker API must run as the unprivileged a2z-control identity")


def _validate_trust_directory(path_text: str, *, required_names: set[str] | None = None,
                              allow_empty: bool = False,
                              require_root_owned: bool) -> None:
    path = Path(path_text)
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("worker public-key trust directory must be a real directory")
    info = path.stat()
    if require_root_owned and os.name == "posix" and info.st_uid != 0:
        raise PermissionError("worker public-key trust directory must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise PermissionError("worker public-key trust directory permissions are too broad")
    for parent in path.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError("worker trust directory parents must be real directories")
        if require_root_owned and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError("worker trust directory parents must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("worker trust directory parents must not be group/other writable")
    entries = list(path.iterdir())
    if len(entries) > 500:
        raise PermissionError("worker trust directory exceeds 500 public keys")
    if not entries and not allow_empty:
        raise PermissionError("worker public-key trust directory must not be empty")
    names: set[str] = set()
    for entry in entries:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}\.pem", entry.name):
            raise PermissionError("worker trust directory has an unexpected entry")
        if entry.is_symlink() or not entry.is_file():
            raise PermissionError("worker trust keys must be regular non-symlink files")
        key_info = entry.stat()
        if require_root_owned and os.name == "posix" and key_info.st_uid != 0:
            raise PermissionError("worker public keys must be root-owned")
        if stat.S_IMODE(key_info.st_mode) & 0o022:
            raise PermissionError("worker public keys must not be group/other writable")
        if key_info.st_size > 16 * 1024:
            raise PermissionError("worker public key exceeds 16 KiB")
        key_bytes = entry.read_bytes()
        if b"-----BEGIN PUBLIC KEY-----" not in key_bytes or b"PRIVATE KEY" in key_bytes:
            raise PermissionError("worker trust entries must contain bounded public-key PEM only")
        names.add(entry.name)
    if required_names and not required_names.issubset(names):
        raise PermissionError("worker registry references a missing trusted public key")


def _validate_disabled_execution_control(path_text: str, *, require_root_owned: bool) -> None:
    path = Path(path_text)
    _check_root_managed_file(path, "execution kill switch", require_root_owned=require_root_owned)
    if stat.S_IMODE(path.stat().st_mode) & 0o027:
        raise PermissionError("execution kill switch must not be group-writable or accessible by other users")
    if path.stat().st_size > 4096:
        raise ValueError("execution kill-switch file exceeds 4096 bytes")
    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    if not isinstance(document, dict) or set(document) != _CONTROL_FIELDS:
        raise ValueError("execution kill-switch fields do not match the contract")
    if document.get("schema_version") != "a2z-execution-control-v1" or document.get("execution_enabled") is not False:
        raise PermissionError("worker API config validation requires the root-managed execution switch to be disabled")


def _check_root_managed_file(path: Path, label: str, *, require_root_owned: bool) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError(f"{label} must be an absolute regular non-symlink file")
    info = path.stat()
    if require_root_owned and os.name == "posix" and info.st_uid != 0:
        raise PermissionError(f"{label} must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError(f"{label} must not be group/other writable")
    for parent in path.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError(f"{label} parent directories must be real directories")
        if require_root_owned and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError(f"{label} parent directories must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError(f"{label} parent directories must not be group/other writable")


def _check_service_private_key(path: Path, *, require_root_owned: bool) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError("worker TLS private key must be a regular non-symlink file")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("worker TLS private key must be a2z-control-owned mode 0600")
    for parent in path.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError("worker TLS private-key parents must be real directories")
        if require_root_owned and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError("worker TLS private-key parents must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("worker TLS private-key parents must not be group/other writable")


def _check_database_path(path: Path, *, require_service_owner: bool) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("worker journal database path must be absolute")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("worker journal parent must be an existing real directory")
    parent_info = parent.stat()
    if require_service_owner and parent_info.st_uid != os.geteuid():
        raise PermissionError("worker journal parent must be owned by the API service identity")
    if stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise PermissionError("worker journal parent must be owner-only")
    for ancestor in parent.parents:
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PermissionError("worker journal ancestors must be real directories")
        if require_service_owner and info.st_uid not in {0, os.geteuid()}:
            raise PermissionError("worker journal ancestor has an untrusted owner")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (mode & stat.S_ISVTX and info.st_uid == 0):
            raise PermissionError("worker journal ancestor is group/other writable")
    if path.is_symlink():
        raise PermissionError("worker journal database must not be a symlink")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or (require_service_owner and info.st_uid != os.geteuid()):
            raise PermissionError("worker journal database must be a service-owned regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("worker journal database must be owner-only")
    return path


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker API configuration key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
