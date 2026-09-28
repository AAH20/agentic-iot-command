from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .worker_api import RunnerCertificateRegistry, RunnerIdentity


MAX_REGISTRY_BYTES = 256 * 1024
_TOP_LEVEL = {"schema_version", "identities"}
_FIELDS = {
    "spiffe_id", "tenant_id", "runner_id", "certificate_sha256",
    "target_ids", "operation_ids", "environments",
}


def load_runner_certificate_registry(path: str | Path, *, require_root_owned: bool = True) -> RunnerCertificateRegistry:
    registry_path = Path(path)
    _check_registry_file(registry_path, require_root_owned=require_root_owned)
    raw = registry_path.read_bytes()
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("runner identity registry exceeds 256 KiB")
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL:
        raise ValueError("runner identity registry fields do not match v1")
    if document["schema_version"] != "a2z-runner-certificate-registry-v1":
        raise ValueError("unsupported runner identity registry version")
    records = document["identities"]
    if not isinstance(records, list) or not records or len(records) > 500:
        raise ValueError("runner identity registry requires 1 to 500 identities")
    identities: dict[str, RunnerIdentity] = {}
    runner_ids: set[str] = set()
    fingerprints: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != _FIELDS:
            raise ValueError("runner identity fields do not match v1")
        lists: dict[str, frozenset[str]] = {}
        for name in ("target_ids", "operation_ids", "environments"):
            values = record[name]
            if (not isinstance(values, list) or not values or len(values) > 500
                    or any(not isinstance(value, str) for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError(f"runner {name} must be a unique non-empty string list")
            lists[name] = frozenset(values)
        identity = RunnerIdentity(
            spiffe_id=record["spiffe_id"], tenant_id=record["tenant_id"],
            runner_id=record["runner_id"], certificate_sha256=record["certificate_sha256"],
            target_ids=lists["target_ids"], operation_ids=lists["operation_ids"],
            environments=lists["environments"],
        )
        if identity.spiffe_id in identities or identity.runner_id in runner_ids:
            raise ValueError("runner SPIFFE and runner IDs must be unique")
        if identity.certificate_sha256 in fingerprints:
            raise ValueError("runner certificate fingerprints must be unique")
        identities[identity.spiffe_id] = identity
        runner_ids.add(identity.runner_id)
        fingerprints.add(identity.certificate_sha256)
    return RunnerCertificateRegistry(identities)


def _check_registry_file(path: Path, *, require_root_owned: bool) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError("runner registry must be an absolute regular non-symlink file")
    info = path.stat()
    if require_root_owned and os.name == "posix" and info.st_uid != 0:
        raise PermissionError("runner registry must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError("runner registry must not be group/other writable")
    for parent in path.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise PermissionError("runner registry parents must be real directories")
        if require_root_owned and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError("runner registry parent directories must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("runner registry parents must not be group/other writable")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate runner registry JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
