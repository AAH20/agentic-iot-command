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


ATTESTATION_DOMAIN = "a2z.runner-attestation.v1"
MAX_ATTESTATION_BYTES = 64 * 1024
_ATTESTATION_FIELDS = {
    "schema_version", "receipt_id", "task_id", "tenant_id", "target_id", "operation_id",
    "environment", "plan_digest", "lease_generation", "runner_id", "started_at", "completed_at",
    "outcome", "changed", "pre_state_sha256", "post_state_sha256", "network_calls", "credentials_issued",
}


class RunnerAttestationVerifier(Protocol):
    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]: ...
    def verify_historical(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]: ...


class Ed25519RunnerAttestationSigner:
    """Create domain-separated runner receipts using an owner-only Ed25519 key."""

    def __init__(self, *, key_id: str, private_key_path: str | Path,
                 openssl_bin: str = "/usr/bin/openssl", timeout_seconds: int = 10) -> None:
        if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id):
            raise ValueError("runner signing key ID is invalid")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("runner signer timeout must be between 1 and 30 seconds")
        self.key_id = key_id
        self.private_key_path = Path(private_key_path)
        self.openssl_bin = Path(openssl_bin)
        self.timeout_seconds = timeout_seconds

    def sign(self, attestation: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(attestation, dict) or set(attestation) != _ATTESTATION_FIELDS:
            raise ValueError("runner attestation fields do not match a2z-runner-attestation-v1")
        payload = _canonical_envelope_payload(attestation)
        if len(payload) > MAX_ATTESTATION_BYTES:
            raise ValueError("runner attestation exceeds 64 KiB")
        self._check_private_key()
        openssl = self.openssl_bin
        if (not openssl.is_absolute() or openssl.is_symlink() or not openssl.is_file()
                or not os.access(openssl, os.X_OK)):
            raise PermissionError("fixed OpenSSL executable is unavailable")
        info = openssl.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("OpenSSL executable must be root-owned and not group/other writable")
        for parent in openssl.parents:
            if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != 0 or stat.S_IMODE(parent.stat().st_mode) & 0o022:
                raise PermissionError("OpenSSL parent directories must be real, root-owned, and not group/other writable")
        with tempfile.TemporaryDirectory(prefix="a2z-runner-sign-") as directory:
            payload_path = Path(directory) / "payload.json"
            signature_path = Path(directory) / "signature.bin"
            payload_path.write_bytes(payload)
            payload_path.chmod(0o600)
            try:
                result = subprocess.run(
                    [str(openssl), "pkeyutl", "-sign", "-rawin", "-inkey",
                     str(self.private_key_path), "-in", str(payload_path), "-out", str(signature_path)],
                    check=False, capture_output=True, timeout=self.timeout_seconds,
                    close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("runner receipt signing failed closed") from exc
            if result.returncode != 0 or not signature_path.is_file() or signature_path.is_symlink():
                raise PermissionError("runner receipt signing failed")
            signature = signature_path.read_bytes()
        if len(signature) != 64:
            raise PermissionError("Ed25519 signer returned an invalid signature length")
        return {
            "attestation": attestation,
            "signature": {
                "algorithm": "ed25519", "key_id": self.key_id,
                "signature_base64": base64.b64encode(signature).decode("ascii"),
            },
        }

    def _check_private_key(self) -> None:
        key = self.private_key_path
        if not key.is_absolute() or key.is_symlink() or not key.is_file():
            raise PermissionError("runner private key must be an absolute regular non-symlink file")
        info = key.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("runner private key must be owned by this runner and inaccessible to group/other users")
        for parent in key.parents:
            if parent.is_symlink() or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) & 0o022:
                raise PermissionError("runner private-key parent directories must be real and not group/other writable")


class Ed25519RunnerAttestationVerifier:
    """Verify domain-separated runner receipts against a root-managed trust store."""

    def __init__(self, trust_dir: str | Path, *, verifier_bin: str | None = None,
                 timeout_seconds: int = 10, require_root_owned_trust: bool = True) -> None:
        self.trust_dir = Path(trust_dir).expanduser()
        self.verifier_bin = verifier_bin or str(Path(__file__).resolve().parents[2] / "scripts" / "verify-runner-attestation.sh")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("attestation verifier timeout must be between 1 and 30 seconds")
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_trust = require_root_owned_trust

    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]:
        return self._verify(envelope, expected_claims=expected_claims, historical=False)

    def verify_historical(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Verify a cryptographically authentic old receipt for explicit journal reconciliation.

        Callers must independently bind signed timestamps to the journal's recorded lease and
        consumed grant. Normal runner submission must continue to use ``verify``.
        """
        return self._verify(envelope, expected_claims=expected_claims, historical=True)

    def _verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any],
                historical: bool) -> tuple[dict[str, Any], str]:
        if not isinstance(envelope, dict) or set(envelope) != {"attestation", "signature"}:
            raise ValueError("runner attestation envelope must contain exactly attestation and signature")
        attestation, signature = envelope["attestation"], envelope["signature"]
        if not isinstance(attestation, dict) or set(attestation) != _ATTESTATION_FIELDS:
            raise ValueError("runner attestation fields do not match a2z-runner-attestation-v1")
        if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "signature_base64"}:
            raise ValueError("runner attestation signature fields are invalid")
        if (signature["algorithm"] != "ed25519" or not isinstance(signature["key_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", signature["key_id"])):
            raise ValueError("runner attestation must use an identified Ed25519 key")
        if not isinstance(signature["signature_base64"], str):
            raise ValueError("runner attestation signature encoding must be a string")
        try:
            base64.b64decode(signature["signature_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("runner attestation signature encoding is invalid") from exc
        if attestation["schema_version"] != "a2z-runner-attestation-v1":
            raise ValueError("unsupported runner attestation schema version")
        for field in ("receipt_id", "task_id"):
            if not isinstance(attestation[field], str):
                raise ValueError(f"runner attestation {field} must be a UUID string")
            try:
                UUID(attestation[field])
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"runner attestation {field} must be a UUID") from exc
        for field in ("tenant_id", "target_id", "operation_id", "runner_id"):
            value = attestation[field]
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"runner attestation {field} must be a bounded non-empty string")
        if not isinstance(attestation["environment"], str) or attestation["environment"] not in {"lab", "development", "staging"}:
            raise PermissionError("runner attestation environment is outside the lab execution profile")
        for field in ("plan_digest", "pre_state_sha256", "post_state_sha256"):
            if not isinstance(attestation[field], str) or not re.fullmatch(r"[0-9a-f]{64}", attestation[field]):
                raise ValueError(f"runner attestation {field} must be a lowercase SHA-256 digest")
        generation = attestation["lease_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise ValueError("runner attestation lease_generation must be positive")
        if attestation["outcome"] not in {"succeeded", "already_satisfied", "failed", "unknown"}:
            raise ValueError("runner attestation outcome is invalid")
        if not isinstance(attestation["changed"], bool) or not isinstance(attestation["credentials_issued"], bool):
            raise ValueError("runner attestation boolean fields are invalid")
        network_calls = attestation["network_calls"]
        if isinstance(network_calls, bool) or not isinstance(network_calls, int) or not 0 <= network_calls <= 10000:
            raise ValueError("runner attestation network_calls must be bounded")
        started = _timestamp(attestation["started_at"], "started_at")
        completed = _timestamp(attestation["completed_at"], "completed_at")
        if completed < started or completed - started > dt.timedelta(minutes=30):
            raise PermissionError("runner attestation time bounds are invalid")
        now = dt.datetime.now(dt.timezone.utc)
        if completed > now + dt.timedelta(minutes=2) or (not historical and now - completed > dt.timedelta(minutes=30)):
            raise PermissionError("runner attestation is outside the accepted freshness window")
        for field, expected in expected_claims.items():
            if field not in _ATTESTATION_FIELDS or attestation[field] != expected:
                raise PermissionError(f"runner attestation claim does not match leased task: {field}")
        canonical = _canonical_envelope_payload(attestation)
        if len(canonical) > MAX_ATTESTATION_BYTES:
            raise ValueError("runner attestation exceeds 64 KiB")
        self._verify_signature(envelope)
        return attestation, hashlib.sha256(canonical).hexdigest()

    def _verify_signature(self, envelope: dict[str, Any]) -> None:
        if self.trust_dir.is_symlink() or not self.trust_dir.is_dir():
            raise PermissionError("runner trust directory must be a real directory")
        trust_stat = self.trust_dir.stat()
        if self.require_root_owned_trust and os.name == "posix" and trust_stat.st_uid != 0:
            raise PermissionError("runner trust directory must be root-owned")
        if stat.S_IMODE(trust_stat.st_mode) & 0o027:
            raise PermissionError("runner trust directory is writable by its group or accessible to other users")
        verifier = Path(self.verifier_bin)
        if not verifier.is_file() or verifier.is_symlink() or not os.access(verifier, os.X_OK):
            raise PermissionError("runner attestation signature verifier is unavailable")
        verifier_info = verifier.stat()
        if self.require_root_owned_trust and os.name == "posix" and verifier_info.st_uid != 0:
            raise PermissionError("runner attestation signature verifier must be root-owned")
        if stat.S_IMODE(verifier_info.st_mode) & 0o022:
            raise PermissionError("runner attestation signature verifier must not be group/other writable")
        with tempfile.TemporaryDirectory(prefix="a2z-runner-attestation-") as directory:
            record = Path(directory) / "attestation.json"
            record.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
            record.chmod(0o600)
            environment = {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "A2Z_RUNNER_TRUST_DIR": str(self.trust_dir),
            }
            try:
                result = subprocess.run(
                    ["/bin/bash", str(verifier), str(record)], check=False,
                    capture_output=True, text=True, timeout=self.timeout_seconds,
                    close_fds=True, env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("runner attestation verification failed closed") from exc
        if result.returncode != 0:
            raise PermissionError("runner attestation signature verification failed")


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"runner attestation {field} must be ISO 8601")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"runner attestation {field} must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"runner attestation {field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _canonical_envelope_payload(attestation: dict[str, Any]) -> bytes:
    return json.dumps(
        {"domain": ATTESTATION_DOMAIN, "attestation": attestation},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
