from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID


class ApprovalVerifier(Protocol):
    def verify(self, signed_record: dict[str, Any], *, expected_scope: dict[str, Any]) -> dict[str, Any]: ...


class Ed25519ApprovalVerifier:
    """Verify signed approval records with the repository's fail-closed verifier."""

    def __init__(self, verifier_bin: str | None = None, *, trust_dir: str | Path | None = None,
                 timeout_seconds: int = 10) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        self.verifier_bin = verifier_bin or os.environ.get(
            "A2Z_APPROVAL_VERIFY_BIN", str(repository_root / "scripts" / "verify-approval.sh")
        )
        self.trust_dir = Path(trust_dir or os.environ.get("A2Z_APPROVAL_TRUST_DIR", "")).expanduser()
        self.timeout_seconds = timeout_seconds

    def verify(self, signed_record: dict[str, Any], *, expected_scope: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(signed_record, dict) or set(signed_record) != {"approval", "signature"}:
            raise ValueError("signed approval must contain exactly approval and signature")
        approval = signed_record["approval"]
        signature = signed_record["signature"]
        if not isinstance(approval, dict) or not isinstance(signature, dict):
            raise ValueError("approval and signature must be objects")
        required = {"approval_id", "request_id", "approver_id", "approved_at", "expires_at", "scope"}
        if set(approval) != required:
            raise ValueError("approval payload fields do not match the required contract")
        if approval["scope"] != expected_scope:
            raise PermissionError("signed approval scope does not match the authorized request")
        if set(signature) != {"algorithm", "key_id", "signature_base64"} or signature.get("algorithm") != "ed25519":
            raise ValueError("approval signature fields must match the Ed25519 contract")
        try:
            approved_at = dt.datetime.fromisoformat(str(approval["approved_at"]).replace("Z", "+00:00"))
            expires_at = dt.datetime.fromisoformat(str(approval["expires_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("approval timestamps must be valid ISO 8601 values") from exc
        if approved_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("approval timestamps must include a timezone")
        now = dt.datetime.now(dt.timezone.utc)
        if approved_at > now or expires_at <= now or expires_at <= approved_at:
            raise PermissionError("approval is not currently valid")
        if not all(isinstance(approval[key], str) and approval[key].strip() for key in ("approval_id", "request_id", "approver_id")):
            raise ValueError("approval identifiers must be non-empty strings")
        try:
            UUID(approval["approval_id"])
            UUID(approval["request_id"])
        except ValueError as exc:
            raise ValueError("approval_id and request_id must be UUIDs") from exc
        if expires_at - approved_at > dt.timedelta(minutes=15):
            raise PermissionError("approval lifetime exceeds the 15 minute local policy")

        verifier = Path(self.verifier_bin)
        if not verifier.is_file() or not os.access(verifier, os.X_OK):
            raise PermissionError("configured approval signature verifier is unavailable")
        with tempfile.TemporaryDirectory(prefix="a2z-approval-") as temporary_directory:
            record_path = Path(temporary_directory) / "signed-approval.json"
            record_path.write_text(json.dumps(signed_record, sort_keys=True, separators=(",", ":")) + "\n")
            record_path.chmod(0o600)
            try:
                result = subprocess.run(
                    [str(verifier), str(record_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    close_fds=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                         "A2Z_APPROVAL_TRUST_DIR": str(self.trust_dir)},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("approval signature verification failed closed") from exc
        if result.returncode != 0:
            raise PermissionError("approval signature verification failed")
        return approval
