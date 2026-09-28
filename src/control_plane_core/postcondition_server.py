from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .goals import DurableGoalStore
from .postcondition_api import (
    AuthenticatedPostconditionAPI,
    build_mtls_postcondition_server,
)
from .postcondition_attestations import (
    Ed25519PostconditionAttestationVerifier,
    _check_key_file,
)
from .postcondition_registry import load_postcondition_verifier_registry
from .worker_api import mtls_server_context


_CONFIG_FIELDS = {
    "schema_version", "database_path", "verifier_registry_path",
    "verifier_trust_directory", "tls_certificate", "tls_private_key",
    "client_ca", "bind_address", "port",
}
_PATH_FIELDS = {
    "database_path", "verifier_registry_path", "verifier_trust_directory",
    "tls_certificate", "tls_private_key", "client_ca",
}


def load_postcondition_api_config(
    config_path: str | Path, *, require_root_owned: bool = True,
) -> dict[str, Any]:
    """Load root-controlled service settings and reject unsafe network/database paths."""
    path = Path(config_path).expanduser()
    config_file = _check_root_managed_file(
        path, label="postcondition API config", require_root_owned=require_root_owned,
    )
    try:
        raw = config_file.read_bytes()
    except OSError as exc:
        raise PermissionError("postcondition API config cannot be read") from exc
    if len(raw) > 64 * 1024:
        raise ValueError("postcondition API config exceeds 64 KiB")
    try:
        config = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("postcondition API config is not strict UTF-8 JSON") from exc
    if not isinstance(config, dict) or set(config) != _CONFIG_FIELDS:
        raise ValueError("postcondition API config fields do not match the v1 contract")
    if config["schema_version"] != "a2z-postcondition-api-config-v1":
        raise ValueError("unsupported postcondition API config version")
    for field in _PATH_FIELDS:
        value = config[field]
        if not isinstance(value, str) or not value or not Path(value).is_absolute():
            raise ValueError(f"{field} must be a non-empty absolute path")
    bind = config["bind_address"]
    if not isinstance(bind, str):
        raise ValueError("bind_address must be a loopback IP address")
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise ValueError("bind_address must be a numeric loopback IP address") from exc
    if not address.is_loopback:
        raise PermissionError("postcondition API may bind only to loopback")
    port = config["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("postcondition API port must be between 1 and 65535")
    config["database_path"] = str(_check_database_path(
        Path(config["database_path"]), require_service_owner=require_root_owned,
    ))
    return config


def build_postcondition_api_service(
    config_path: str | Path, *, require_root_owned: bool = True,
):
    """Construct the journal-side mTLS API from reviewed config; never starts execution."""
    _require_unprivileged_service_account(require_root_owned)
    config, registry, verifier, tls_context = _load_runtime_settings(
        config_path, require_root_owned=require_root_owned,
    )
    store = DurableGoalStore(config["database_path"])
    api = AuthenticatedPostconditionAPI(store=store, verifier=verifier)
    try:
        server = build_mtls_postcondition_server(
            api=api, registry=registry, tls_context=tls_context,
            address=(config["bind_address"], config["port"]),
        )
    except Exception:
        store.close()
        raise
    return server, store


def validate_postcondition_api_configuration(
    config_path: str | Path, *, require_root_owned: bool = True,
) -> None:
    """Validate service trust/configuration without opening the journal or binding a socket."""
    _require_unprivileged_service_account(require_root_owned)
    _load_runtime_settings(config_path, require_root_owned=require_root_owned)


def _require_unprivileged_service_account(require_root_owned: bool) -> None:
    if require_root_owned and os.name == "posix" and os.geteuid() == 0:
        raise PermissionError("postcondition API must run as a dedicated unprivileged service account")


def _load_runtime_settings(config_path: str | Path, *, require_root_owned: bool):
    config = load_postcondition_api_config(config_path, require_root_owned=require_root_owned)
    registry = load_postcondition_verifier_registry(
        config["verifier_registry_path"], require_root_owned=require_root_owned,
    )
    trust_dir = Path(config["verifier_trust_directory"])
    _validate_public_trust_directory(trust_dir, require_root_owned=require_root_owned)
    verifier_ids = frozenset(identity.verifier_id for identity in registry._identities.values())
    verifier = Ed25519PostconditionAttestationVerifier(
        trust_dir, allowed_verifier_ids=verifier_ids,
        require_root_owned_trust=require_root_owned,
    )
    _check_root_managed_file(
        Path(config["tls_certificate"]), label="postcondition TLS certificate",
        require_root_owned=require_root_owned,
    )
    _check_root_managed_file(
        Path(config["client_ca"]), label="postcondition client CA",
        require_root_owned=require_root_owned,
    )
    _check_service_private_key(
        Path(config["tls_private_key"]), require_root_owned=require_root_owned,
    )
    tls_context = mtls_server_context(
        certificate=config["tls_certificate"], private_key=config["tls_private_key"],
        client_ca=config["client_ca"], require_root_owned=False,
    )
    return config, registry, verifier, tls_context


def _check_database_path(path: Path, *, require_service_owner: bool) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("database_path must be an absolute file path")
    try:
        resolved = path.resolve(strict=path.exists())
    except OSError as exc:
        raise PermissionError("goal journal path cannot be resolved safely") from exc
    parent = resolved.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("goal journal parent must be an existing real directory")
    parent_info = parent.stat()
    if require_service_owner and parent_info.st_uid != os.geteuid():
        raise PermissionError("goal journal parent must belong to the API service account")
    if stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise PermissionError("goal journal parent must not be accessible to group or other users")
    for original_parent in (path.parent, *path.parent.parents):
        info = original_parent.lstat()
        if stat.S_ISLNK(info.st_mode) and info.st_uid != 0:
            raise PermissionError("goal journal path may traverse only root-owned symlinks")
    for ancestor in parent.parents:
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PermissionError("goal journal ancestors must be real directories")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (mode & stat.S_ISVTX and info.st_uid == 0):
            raise PermissionError("goal journal path traverses an unsafe writable directory")
        if info.st_uid not in {0, os.geteuid()}:
            raise PermissionError("goal journal ancestors have an untrusted owner")
    if path.is_symlink() or resolved.is_symlink():
        raise PermissionError("goal journal database may not be a symlink")
    if resolved.exists():
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("goal journal database must be a regular file")
        if require_service_owner and info.st_uid != os.geteuid():
            raise PermissionError("goal journal database must belong to the API service account")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("goal journal database must be owner-only")
    return resolved


def _validate_public_trust_directory(path: Path, *, require_root_owned: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("postcondition signature trust path must be a real directory")
    info = path.stat()
    if require_root_owned and os.name == "posix" and info.st_uid != 0:
        raise PermissionError("postcondition signature trust directory must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise PermissionError("postcondition signature trust directory permissions are too broad")
    for original_parent in path.parents:
        parent_info = original_parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) and parent_info.st_uid != 0:
            raise PermissionError("postcondition trust path may traverse only root-owned symlinks")
    resolved = path.resolve(strict=True)
    for parent in resolved.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError("postcondition signature trust parents must be real directories")
        if require_root_owned and parent_info.st_uid != 0:
            raise PermissionError("postcondition signature trust parents must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("postcondition signature trust parents may not be group/other writable")
    keys = sorted(path.iterdir())
    if not keys:
        raise PermissionError("postcondition signature trust directory must contain a reviewed public key")
    for key in keys:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}\.pem", key.name):
            raise PermissionError("postcondition signature trust directory contains an unexpected entry")
        _check_key_file(key, private=False, require_root_owned=require_root_owned)


def _check_service_private_key(path: Path, *, require_root_owned: bool) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError("postcondition TLS private key must be an absolute regular non-symlink file")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("postcondition TLS private key must be service-owned and owner-only")
    for original_parent in path.parents:
        parent_info = original_parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) and parent_info.st_uid != 0:
            raise PermissionError("TLS private-key path may traverse only root-owned symlinks")
    for parent in resolved.parents:
        parent_info = parent.lstat()
        allowed_owners = {0} if require_root_owned else {0, os.geteuid()}
        if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid not in allowed_owners
                or stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise PermissionError("TLS private-key parent directories have an untrusted owner or writable mode")


def _check_root_managed_file(path: Path, *, label: str, require_root_owned: bool) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError(f"{label} must be an absolute regular non-symlink file")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if require_root_owned and info.st_uid != 0:
        raise PermissionError(f"{label} must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise PermissionError(f"{label} permissions are too broad")
    for original_parent in path.parents:
        parent_info = original_parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode):
            if parent_info.st_uid != 0:
                raise PermissionError(f"{label} path may traverse only root-owned symlinks")
    for parent in resolved.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError(f"{label} resolved parents must be real directories")
        if require_root_owned and parent_info.st_uid != 0:
            raise PermissionError(f"{label} parent directories must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError(f"{label} parent directories may not be group/other writable")
    return resolved


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate postcondition API config key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
