from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .postcondition_api import (
    PostconditionVerifierCertificateRegistry,
    PostconditionVerifierIdentity,
)


MAX_REGISTRY_BYTES = 256 * 1024
_TOP_LEVEL = {"schema_version", "identities"}
_IDENTITY_FIELDS = {
    "spiffe_id", "verifier_id", "tenant_id", "certificate_sha256",
    "target_ids", "operation_ids", "environments",
}


def load_postcondition_verifier_registry(
    path: str | Path, *, require_root_owned: bool = True,
) -> PostconditionVerifierCertificateRegistry:
    """Load a strict, root-managed verifier scope registry; never infer defaults."""
    registry_path = Path(path).expanduser()
    resolved_path = _check_registry_path(registry_path, require_root_owned=require_root_owned)
    try:
        raw = resolved_path.read_bytes()
    except OSError as exc:
        raise PermissionError("postcondition verifier registry cannot be read") from exc
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("postcondition verifier registry exceeds 256 KiB")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("postcondition verifier registry is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL:
        raise ValueError("postcondition verifier registry fields do not match the v1 contract")
    if document["schema_version"] != "a2z-postcondition-verifier-registry-v1":
        raise ValueError("unsupported postcondition verifier registry version")
    records = document["identities"]
    if not isinstance(records, list) or not records or len(records) > 500:
        raise ValueError("postcondition verifier registry requires 1 to 500 identities")

    identities: dict[str, PostconditionVerifierIdentity] = {}
    verifier_ids: set[str] = set()
    fingerprints: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != _IDENTITY_FIELDS:
            raise ValueError("postcondition verifier identity fields do not match the v1 contract")
        for field in ("target_ids", "operation_ids", "environments"):
            values = record[field]
            if (not isinstance(values, list) or not values or len(values) > 500
                    or any(not isinstance(value, str) for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError(f"postcondition verifier {field} must be a unique non-empty string list")
        identity = PostconditionVerifierIdentity(
            spiffe_id=record["spiffe_id"], verifier_id=record["verifier_id"],
            tenant_id=record["tenant_id"], certificate_sha256=record["certificate_sha256"],
            target_ids=frozenset(record["target_ids"]),
            operation_ids=frozenset(record["operation_ids"]),
            environments=frozenset(record["environments"]),
        )
        if identity.spiffe_id in identities:
            raise ValueError("postcondition verifier registry contains duplicate SPIFFE identities")
        if identity.verifier_id in verifier_ids:
            raise ValueError("postcondition verifier IDs must be unique")
        if identity.certificate_sha256 in fingerprints:
            raise ValueError("postcondition verifier certificate fingerprints must be unique")
        identities[identity.spiffe_id] = identity
        verifier_ids.add(identity.verifier_id)
        fingerprints.add(identity.certificate_sha256)
    return PostconditionVerifierCertificateRegistry(identities)


def _check_registry_path(path: Path, *, require_root_owned: bool) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError("postcondition registry path must be an absolute regular non-symlink file")
    if os.name == "posix":
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise PermissionError("postcondition registry path cannot be resolved safely") from exc
        info = resolved_path.stat()
        if require_root_owned and info.st_uid != 0:
            raise PermissionError("postcondition verifier registry must be root-owned")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("postcondition verifier registry may not be group/other writable")
        for parent in path.parents:
            parent_info = parent.lstat()
            if stat.S_ISLNK(parent_info.st_mode):
                if parent_info.st_uid != 0:
                    raise PermissionError("postcondition registry path may traverse only root-owned symlinks")
                continue
            if not stat.S_ISDIR(parent_info.st_mode):
                raise PermissionError("postcondition registry parents must be real directories")
        # Validate the actual directory tree behind any allowed root-owned links.
        for parent in resolved_path.parents:
            parent_info = parent.lstat()
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
                raise PermissionError("resolved postcondition registry parents must be real directories")
            if require_root_owned and parent_info.st_uid != 0:
                raise PermissionError("postcondition registry parent directories must be root-owned")
            if stat.S_IMODE(parent_info.st_mode) & 0o022:
                raise PermissionError("postcondition registry parent directories may not be group/other writable")
        return resolved_path
    return path


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate postcondition registry key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
