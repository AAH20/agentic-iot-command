from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID


POSTCONDITION_DOMAIN = "a2z.postcondition-attestation.v1"
_FIELDS = {
    "schema_version", "verification_id", "receipt_id", "task_id", "tenant_id",
    "target_id", "operation_id", "environment", "plan_digest", "lease_generation",
    "verifier_id", "observed_at", "observed_state",
}


class PostconditionAttestationVerifier(Protocol):
    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]: ...


class Ed25519PostconditionAttestationSigner:
    """Sign observations with a verifier key distinct from the execution runner key."""

    def __init__(self, *, key_id: str, private_key_path: str | Path,
                 openssl_bin: str = "/usr/bin/openssl", timeout_seconds: int = 10) -> None:
        _validate_key_id(key_id)
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("postcondition signer timeout must be between 1 and 30 seconds")
        self.key_id = key_id
        self.private_key_path = Path(private_key_path)
        self.openssl_bin = Path(openssl_bin)
        self.timeout_seconds = timeout_seconds

    def sign(self, attestation: dict[str, Any]) -> dict[str, Any]:
        _validate_attestation(attestation)
        payload = _payload(attestation)
        _check_key_file(self.private_key_path, private=True)
        _check_openssl(self.openssl_bin)
        with tempfile.TemporaryDirectory(prefix="a2z-postcondition-sign-") as directory:
            input_path, signature_path = Path(directory) / "payload.json", Path(directory) / "signature.bin"
            input_path.write_bytes(payload)
            input_path.chmod(0o600)
            try:
                result = subprocess.run(
                    [str(self.openssl_bin), "pkeyutl", "-sign", "-rawin", "-inkey",
                     str(self.private_key_path), "-in", str(input_path), "-out", str(signature_path)],
                    check=False, capture_output=True, timeout=self.timeout_seconds,
                    close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("postcondition signing failed closed") from exc
            if result.returncode != 0 or not signature_path.is_file() or signature_path.is_symlink():
                raise PermissionError("postcondition signing failed")
            signature = signature_path.read_bytes()
        if len(signature) != 64:
            raise PermissionError("Ed25519 postcondition signature has an invalid length")
        return {"attestation": attestation, "signature": {
            "algorithm": "ed25519", "key_id": self.key_id,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }}


class Ed25519PostconditionAttestationVerifier:
    """Validate and verify independent postcondition evidence from a separate trust domain."""

    def __init__(self, trust_dir: str | Path, *, allowed_verifier_ids: frozenset[str],
                 openssl_bin: str = "/usr/bin/openssl",
                 timeout_seconds: int = 10, require_root_owned_trust: bool = True) -> None:
        self.trust_dir = Path(trust_dir).expanduser()
        self.openssl_bin = Path(openssl_bin)
        if (not isinstance(allowed_verifier_ids, frozenset) or not allowed_verifier_ids
                or any(not isinstance(value, str) or not value.strip() or len(value) > 256
                       for value in allowed_verifier_ids)):
            raise ValueError("at least one explicit trusted verifier identity is required")
        self.allowed_verifier_ids = allowed_verifier_ids
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("postcondition verifier timeout must be between 1 and 30 seconds")
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_trust = require_root_owned_trust

    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]:
        if not isinstance(envelope, dict) or set(envelope) != {"attestation", "signature"}:
            raise ValueError("postcondition envelope must contain exactly attestation and signature")
        attestation, signature = envelope["attestation"], envelope["signature"]
        _validate_attestation(attestation)
        if attestation["verifier_id"] not in self.allowed_verifier_ids:
            raise PermissionError("postcondition signer identity is not enrolled for independent verification")
        if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "signature_base64"}:
            raise ValueError("postcondition signature fields are invalid")
        _validate_key_id(signature["key_id"])
        if signature["algorithm"] != "ed25519" or not isinstance(signature["signature_base64"], str):
            raise ValueError("postcondition signature must use Ed25519 base64 encoding")
        try:
            raw_signature = base64.b64decode(signature["signature_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("postcondition signature encoding is invalid") from exc
        if len(raw_signature) != 64:
            raise ValueError("postcondition signature has an invalid length")
        for field, expected in expected_claims.items():
            if field not in _FIELDS or attestation.get(field) != expected:
                raise PermissionError(f"postcondition claim does not match task or receipt: {field}")
        payload = _payload(attestation)
        self._verify_signature(signature["key_id"], payload, raw_signature)
        return attestation, hashlib.sha256(payload).hexdigest()

    def _verify_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        trust_dir = self.trust_dir
        if trust_dir.is_symlink() or not trust_dir.is_dir():
            raise PermissionError("postcondition trust directory must be a real directory")
        directory_info = trust_dir.stat()
        if self.require_root_owned_trust and os.name == "posix" and directory_info.st_uid != 0:
            raise PermissionError("postcondition trust directory must be root-owned")
        if stat.S_IMODE(directory_info.st_mode) & 0o027:
            raise PermissionError("postcondition trust directory permissions are too broad")
        public_key = trust_dir / f"{key_id}.pem"
        _check_key_file(public_key, private=False,
                        require_root_owned=self.require_root_owned_trust)
        _check_openssl(self.openssl_bin)
        with tempfile.TemporaryDirectory(prefix="a2z-postcondition-verify-") as directory:
            input_path, signature_path = Path(directory) / "payload.json", Path(directory) / "signature.bin"
            input_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            input_path.chmod(0o600)
            signature_path.chmod(0o600)
            try:
                result = subprocess.run(
                    [str(self.openssl_bin), "pkeyutl", "-verify", "-pubin", "-inkey",
                     str(public_key), "-rawin", "-in", str(input_path), "-sigfile", str(signature_path)],
                    check=False, capture_output=True, timeout=self.timeout_seconds,
                    close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("postcondition signature verification failed closed") from exc
        if result.returncode != 0:
            raise PermissionError("postcondition signature verification failed")


def _validate_attestation(attestation: Any) -> None:
    if not isinstance(attestation, dict) or set(attestation) != _FIELDS:
        raise ValueError("postcondition attestation fields do not match the v1 contract")
    if attestation["schema_version"] != "a2z-postcondition-attestation-v1":
        raise ValueError("unsupported postcondition attestation version")
    for field in ("verification_id", "receipt_id", "task_id"):
        if not isinstance(attestation[field], str):
            raise ValueError(f"postcondition {field} must be a UUID string")
        try:
            UUID(attestation[field])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"postcondition {field} must be a UUID") from exc
    for field in ("tenant_id", "target_id", "operation_id", "verifier_id"):
        value = attestation[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"postcondition {field} must be a bounded non-empty string")
    if (not isinstance(attestation["environment"], str)
            or attestation["environment"] not in {"lab", "development", "staging"}):
        raise PermissionError("postcondition environment is outside the non-production verifier profile")
    if not isinstance(attestation["plan_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", attestation["plan_digest"]):
        raise ValueError("postcondition plan_digest must be a lowercase SHA-256 digest")
    generation = attestation["lease_generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("postcondition lease_generation must be positive")
    observed_at = _timestamp(attestation["observed_at"])
    now = dt.datetime.now(dt.timezone.utc)
    if observed_at > now + dt.timedelta(minutes=2) or now - observed_at > dt.timedelta(minutes=10):
        raise PermissionError("postcondition observation is outside the freshness window")
    state = attestation["observed_state"]
    if (not isinstance(state, dict) or set(state) != {"power_state", "description"}
            or not isinstance(state.get("power_state"), str)
            or state["power_state"] not in {"powered_off", "running", "paused"}
            or not isinstance(state.get("description"), str) or len(state["description"]) > 256):
        raise ValueError("observed VirtualBox state does not match the typed read-only contract")


def _payload(attestation: dict[str, Any]) -> bytes:
    return json.dumps({"domain": POSTCONDITION_DOMAIN, "attestation": attestation}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _validate_key_id(value: Any) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        raise ValueError("postcondition key ID is invalid")


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("postcondition observed_at must be ISO 8601")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("postcondition observed_at must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("postcondition observed_at must include timezone")
    return parsed.astimezone(dt.timezone.utc)


def _check_key_file(path: Path, *, private: bool, require_root_owned: bool = False) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PermissionError("postcondition key path must be an absolute regular non-symlink file")
    info = path.stat()
    if private:
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("postcondition private key must be runner-owned and owner-only")
    else:
        if require_root_owned and os.name == "posix" and info.st_uid != 0:
            raise PermissionError("postcondition public key must be root-owned")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("postcondition public key must not be group/other writable")
    for parent in path.parents:
        parent_info = parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode):
            if parent_info.st_uid != 0:
                raise PermissionError("postcondition key path may traverse only root-owned symlinks")
            continue
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise PermissionError("postcondition key parent directories are not trusted")


def _check_openssl(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise PermissionError("fixed system OpenSSL executable is unavailable")
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError("OpenSSL executable must be root-owned and not group/other writable")
    for parent in path.parents:
        parent_info = parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
                or stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise PermissionError("OpenSSL parent directories must be root-owned and not group/other writable")
