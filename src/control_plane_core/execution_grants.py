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


GRANT_DOMAIN = "a2z.execution-grant.v2"
MAX_GRANT_BYTES = 32 * 1024
_FIELDS = {
    "schema_version", "grant_id", "task_id", "tenant_id", "target_id", "operation_id",
    "environment", "plan_digest", "authorization_mode", "authorization_id",
    "approval_id", "policy_digest", "impact_assessment_digest", "lease_generation", "runner_id",
    "lease_token_sha256", "issued_at", "expires_at", "max_runtime_seconds",
}
_EXPECTED_FIELDS = {
    "task_id", "tenant_id", "target_id", "operation_id", "environment", "plan_digest",
    "authorization_mode", "authorization_id", "approval_id", "policy_digest",
    "impact_assessment_digest", "lease_generation", "runner_id", "lease_token_sha256",
}


class ExecutionGrantVerifier(Protocol):
    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]: ...


class ExecutionGrantSigner(Protocol):
    def sign(self, grant: dict[str, Any]) -> dict[str, Any]: ...


class Ed25519ExecutionGrantSigner:
    """Sign grants with a root-managed, owner-only Ed25519 private key."""

    def __init__(self, private_key: str | Path, *, key_id: str, timeout_seconds: int = 10,
                 require_root_owned_key: bool = True) -> None:
        self.private_key = Path(private_key).expanduser()
        if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id):
            raise ValueError("execution-grant signing key_id is invalid")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("execution-grant signing timeout must be between 1 and 30 seconds")
        self.key_id = key_id
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_key = require_root_owned_key

    def sign(self, grant: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(grant, dict) or set(grant) != _FIELDS:
            raise ValueError("only a complete a2z-execution-grant-v2 payload may be signed")
        if len(_canonical_payload(grant)) > MAX_GRANT_BYTES:
            raise ValueError("execution grant exceeds 32 KiB")
        if self.private_key.is_symlink() or not self.private_key.is_file():
            raise PermissionError("execution-grant signing key must be a regular non-symlink file")
        key_info = self.private_key.stat()
        if self.require_root_owned_key and os.name == "posix" and key_info.st_uid != 0:
            raise PermissionError("execution-grant signing key must be root-owned")
        if stat.S_IMODE(key_info.st_mode) & 0o077:
            raise PermissionError("execution-grant signing key must be owner-only")
        parent = self.private_key.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("execution-grant signing key parent must be a real directory")
        parent_info = parent.stat()
        if self.require_root_owned_key and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError("execution-grant signing key parent must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("execution-grant signing key parent must not be group/other writable")
        openssl = Path("/usr/bin/openssl")
        if openssl.is_symlink() or not openssl.is_file() or not os.access(openssl, os.X_OK):
            raise PermissionError("fixed system OpenSSL executable is unavailable")
        openssl_info = openssl.stat()
        if os.name == "posix" and openssl_info.st_uid != 0:
            raise PermissionError("fixed system OpenSSL executable must be root-owned")
        if stat.S_IMODE(openssl_info.st_mode) & 0o022:
            raise PermissionError("fixed system OpenSSL executable must not be group/other writable")
        with tempfile.TemporaryDirectory(prefix="a2z-execution-grant-sign-") as directory:
            payload = Path(directory) / "payload.json"
            signature = Path(directory) / "signature.bin"
            payload.write_bytes(_canonical_payload(grant))
            payload.chmod(0o600)
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
            try:
                result = subprocess.run(
                    ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key), "-rawin",
                     "-in", str(payload), "-out", str(signature)],
                    check=False, capture_output=True, text=True, timeout=self.timeout_seconds,
                    close_fds=True, env=env,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("execution-grant signing failed closed") from exc
            if result.returncode != 0 or not signature.is_file():
                raise PermissionError("execution-grant signing failed")
            encoded = base64.b64encode(signature.read_bytes()).decode("ascii")
        return {
            "grant": grant,
            "signature": {"algorithm": "ed25519", "key_id": self.key_id, "signature_base64": encoded},
        }


class Ed25519ExecutionGrantVerifier:
    """Fail-closed verifier for short-lived, exact-scope runner capabilities."""

    def __init__(self, trust_dir: str | Path, *, verifier_bin: str | None = None,
                 timeout_seconds: int = 10, require_root_owned_trust: bool = True) -> None:
        self.trust_dir = Path(trust_dir).expanduser()
        self.verifier_bin = verifier_bin or str(Path(__file__).resolve().parents[2] / "scripts" / "verify-execution-grant.sh")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("execution-grant verifier timeout must be between 1 and 30 seconds")
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_trust = require_root_owned_trust

    def verify(self, envelope: dict[str, Any], *, expected_claims: dict[str, Any]) -> tuple[dict[str, Any], str]:
        if not isinstance(envelope, dict) or set(envelope) != {"grant", "signature"}:
            raise ValueError("execution grant envelope must contain exactly grant and signature")
        grant, signature = envelope["grant"], envelope["signature"]
        if not isinstance(grant, dict) or set(grant) != _FIELDS:
            raise ValueError("execution grant fields do not match a2z-execution-grant-v2")
        if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "signature_base64"}:
            raise ValueError("execution grant signature fields are invalid")
        if (signature["algorithm"] != "ed25519" or not isinstance(signature["key_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", signature["key_id"])):
            raise ValueError("execution grant must use an identified Ed25519 key")
        if not isinstance(signature["signature_base64"], str):
            raise ValueError("execution grant signature encoding must be a string")
        try:
            base64.b64decode(signature["signature_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("execution grant signature encoding is invalid") from exc
        if grant["schema_version"] != "a2z-execution-grant-v2":
            raise ValueError("unsupported execution grant schema version")
        for field in ("grant_id", "task_id", "authorization_id"):
            if not isinstance(grant[field], str):
                raise ValueError(f"execution grant {field} must be a UUID string")
            try:
                UUID(grant[field])
            except ValueError as exc:
                raise ValueError(f"execution grant {field} must be a UUID") from exc
        mode = grant["authorization_mode"]
        if not isinstance(mode, str):
            raise ValueError("execution grant authorization_mode is invalid")
        if mode not in {"operator_approval", "standing_policy"}:
            raise ValueError("execution grant authorization_mode is unsupported")
        if mode == "operator_approval":
            if grant["approval_id"] != grant["authorization_id"] or any(
                    grant[field] is not None for field in ("policy_digest", "impact_assessment_digest")):
                raise PermissionError("operator-approval grant authorization binding is inconsistent")
        else:
            if grant["approval_id"] is not None:
                raise PermissionError("standing-policy grant must not claim a human approval")
            for field in ("policy_digest", "impact_assessment_digest"):
                if not isinstance(grant[field], str) or not re.fullmatch(r"[0-9a-f]{64}", grant[field]):
                    raise PermissionError(f"standing-policy grant requires a valid {field}")
        for field in ("tenant_id", "target_id", "operation_id", "runner_id"):
            value = grant[field]
            if not isinstance(value, str) or not value.strip() or len(value) > 256 or value == "*":
                raise ValueError(f"execution grant {field} must be a specific bounded identifier")
        if not isinstance(grant["environment"], str) or grant["environment"] not in {"lab", "development", "staging"}:
            raise PermissionError("execution grant is outside the non-production execution profile")
        for field in ("plan_digest", "lease_token_sha256"):
            if not isinstance(grant[field], str) or not re.fullmatch(r"[0-9a-f]{64}", grant[field]):
                raise ValueError(f"execution grant {field} must be a lowercase SHA-256 digest")
        generation = grant["lease_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise ValueError("execution grant lease_generation must be positive")
        runtime = grant["max_runtime_seconds"]
        if isinstance(runtime, bool) or not isinstance(runtime, int) or not 1 <= runtime <= 300:
            raise PermissionError("execution grant runtime exceeds the 5-minute worker limit")
        issued = _timestamp(grant["issued_at"], "issued_at")
        expires = _timestamp(grant["expires_at"], "expires_at")
        now = dt.datetime.now(dt.timezone.utc)
        if (issued > now + dt.timedelta(seconds=15) or expires <= now or expires <= issued
                or expires - issued > dt.timedelta(minutes=10)
                or expires - issued > dt.timedelta(seconds=runtime)):
            raise PermissionError("execution grant is expired, not yet valid, or exceeds the lease bound")
        if not isinstance(expected_claims, dict) or set(expected_claims) != _EXPECTED_FIELDS:
            raise ValueError("runner must supply every required live lease claim")
        for field, expected in expected_claims.items():
            if grant[field] != expected:
                raise PermissionError(f"execution grant does not match live lease: {field}")
        canonical = _canonical_payload(grant)
        if len(canonical) > MAX_GRANT_BYTES:
            raise ValueError("execution grant exceeds 32 KiB")
        self._verify_signature(envelope)
        return grant, hashlib.sha256(canonical).hexdigest()

    def _verify_signature(self, envelope: dict[str, Any]) -> None:
        if self.trust_dir.is_symlink() or not self.trust_dir.is_dir():
            raise PermissionError("execution-grant trust directory must be a real directory")
        info = self.trust_dir.stat()
        if self.require_root_owned_trust and os.name == "posix" and info.st_uid != 0:
            raise PermissionError("execution-grant trust directory must be root-owned")
        if stat.S_IMODE(info.st_mode) & 0o027:
            raise PermissionError("execution-grant trust directory permissions are too broad")
        verifier = Path(self.verifier_bin)
        if not verifier.is_file() or verifier.is_symlink() or not os.access(verifier, os.X_OK):
            raise PermissionError("execution-grant signature verifier is unavailable")
        verifier_info = verifier.stat()
        if self.require_root_owned_trust and os.name == "posix" and verifier_info.st_uid != 0:
            raise PermissionError("execution-grant signature verifier must be root-owned")
        if stat.S_IMODE(verifier_info.st_mode) & 0o022:
            raise PermissionError("execution-grant signature verifier must not be group/other writable")
        with tempfile.TemporaryDirectory(prefix="a2z-execution-grant-") as directory:
            record = Path(directory) / "grant.json"
            record.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
            record.chmod(0o600)
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "A2Z_EXECUTION_GRANT_TRUST_DIR": str(self.trust_dir)}
            try:
                result = subprocess.run(
                    ["/bin/bash", str(verifier), str(record)], check=False, capture_output=True,
                    text=True, timeout=self.timeout_seconds, close_fds=True, env=env,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("execution-grant signature verification failed closed") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            reason = detail[-1][:240] if detail else f"verifier exited with status {result.returncode}"
            raise PermissionError(f"execution-grant signature verification failed: {reason}")


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"execution grant {field} must be ISO 8601")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"execution grant {field} must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"execution grant {field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _canonical_payload(grant: dict[str, Any]) -> bytes:
    return json.dumps(
        {"domain": GRANT_DOMAIN, "grant": grant},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
