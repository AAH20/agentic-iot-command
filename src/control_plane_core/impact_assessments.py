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
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID


DOMAIN = "a2z.impact-assessment.v1"
SCHEMA_VERSION = "a2z-impact-assessment-v1"
MAX_ASSESSMENT_BYTES = 32 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_ASSESSMENT_LIFETIME = dt.timedelta(minutes=10)
_FIELDS = {
    "schema_version", "assessment_id", "tenant_id", "task_id", "operation_id",
    "target_ids", "environment", "plan_digest", "affected_resource_count",
    "estimated_cost_microusd", "source_id", "generated_at", "expires_at",
}


@dataclass(frozen=True)
class VerifiedImpactAssessment:
    tenant_id: str
    task_id: str
    operation_id: str
    target_ids: tuple[str, ...]
    environment: str
    plan_digest: str
    affected_resource_count: int
    estimated_cost_microusd: int
    source_id: str
    assessment_digest: str
    expires_at: dt.datetime


class ImpactAssessmentVerifier:
    """Verify a fresh, exact-plan assessment signed by a root-trusted estimator."""

    def __init__(self, trust_dir: str | Path, *, timeout_seconds: int = 10,
                 require_root_owned_trust: bool = True) -> None:
        self.trust_dir = Path(trust_dir).expanduser()
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("impact assessment verifier timeout must be between 1 and 30 seconds")
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_trust = require_root_owned_trust
        package_root = Path(__file__).resolve().parents[2]
        self._verifier = package_root / "scripts" / "verify-impact-assessment.sh"

    def verify(self, envelope: dict[str, Any], *, expected: dict[str, Any],
               now: dt.datetime | None = None) -> VerifiedImpactAssessment:
        if not isinstance(envelope, dict) or set(envelope) != {"assessment", "signature"}:
            raise ValueError("impact assessment envelope must contain exactly assessment and signature")
        try:
            encoded_envelope = json.dumps(
                envelope, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("impact assessment envelope is not strict JSON") from exc
        if len(encoded_envelope) > MAX_ENVELOPE_BYTES:
            raise ValueError("impact assessment envelope exceeds 64 KiB")
        assessment, signature = envelope["assessment"], envelope["signature"]
        if not isinstance(assessment, dict) or set(assessment) != _FIELDS:
            raise ValueError("impact assessment fields do not match a2z-impact-assessment-v1")
        if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "signature_base64"}:
            raise ValueError("impact assessment signature fields are invalid")
        if (signature["algorithm"] != "ed25519" or not isinstance(signature["key_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", signature["key_id"])):
            raise ValueError("impact assessment must use an identified Ed25519 key")
        if not isinstance(signature["signature_base64"], str):
            raise ValueError("impact assessment signature encoding is invalid")
        try:
            base64.b64decode(signature["signature_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("impact assessment signature encoding is invalid") from exc
        if assessment["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported impact assessment schema version")
        for field in ("assessment_id", "task_id"):
            if not isinstance(assessment[field], str):
                raise ValueError(f"impact assessment {field} must be a UUID")
            try:
                UUID(assessment[field])
            except ValueError as exc:
                raise ValueError(f"impact assessment {field} must be a UUID") from exc
        for field in ("tenant_id", "operation_id", "source_id"):
            value = assessment[field]
            if not isinstance(value, str) or not value.strip() or len(value) > 256 or value == "*":
                raise ValueError(f"impact assessment {field} must be a specific bounded identifier")
        targets = assessment["target_ids"]
        if (not isinstance(targets, list) or not targets or len(targets) > 500
                or any(not isinstance(item, str) or not item.strip() or item == "*" or len(item) > 256 for item in targets)
                or len(set(targets)) != len(targets)):
            raise ValueError("impact assessment target_ids must be a unique non-empty exact target list")
        if not isinstance(assessment["environment"], str) or assessment["environment"] not in {"lab", "development", "staging"}:
            raise PermissionError("impact assessment is outside non-production scope")
        if not isinstance(assessment["plan_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", assessment["plan_digest"]):
            raise ValueError("impact assessment plan_digest must be a lowercase SHA-256 digest")
        for field, maximum in (("affected_resource_count", 1_000_000), ("estimated_cost_microusd", 10**12)):
            value = assessment[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"impact assessment {field} is outside its bounded range")
        if not isinstance(expected, dict) or set(expected) != {
            "tenant_id", "task_id", "operation_id", "target_ids", "environment", "plan_digest",
        }:
            raise ValueError("all exact task and plan claims are required to verify an impact assessment")
        for field, expected_value in expected.items():
            actual = tuple(targets) if field == "target_ids" else assessment[field]
            if actual != expected_value:
                raise PermissionError(f"impact assessment does not match current task: {field}")
        generated = _timestamp(assessment["generated_at"], "generated_at")
        expires = _timestamp(assessment["expires_at"], "expires_at")
        current = now or dt.datetime.now(dt.timezone.utc)
        if current.tzinfo is None:
            raise ValueError("impact assessment verification clock must include a timezone")
        if generated > current + dt.timedelta(seconds=15) or expires <= current or expires <= generated:
            raise PermissionError("impact assessment is not currently valid")
        if expires - generated > MAX_ASSESSMENT_LIFETIME:
            raise PermissionError("impact assessment lifetime exceeds 10 minutes")
        canonical = _canonical(assessment)
        if len(canonical) > MAX_ASSESSMENT_BYTES:
            raise ValueError("impact assessment exceeds 32 KiB")
        self._verify_signature(envelope)
        return VerifiedImpactAssessment(
            tenant_id=assessment["tenant_id"], task_id=assessment["task_id"],
            operation_id=assessment["operation_id"], target_ids=tuple(targets),
            environment=assessment["environment"], plan_digest=assessment["plan_digest"],
            affected_resource_count=assessment["affected_resource_count"],
            estimated_cost_microusd=assessment["estimated_cost_microusd"],
            source_id=assessment["source_id"], assessment_digest=hashlib.sha256(canonical).hexdigest(),
            expires_at=expires,
        )

    def _verify_signature(self, envelope: dict[str, Any]) -> None:
        trust_dir = self.trust_dir
        if trust_dir.is_symlink() or not trust_dir.is_dir():
            raise PermissionError("impact assessment trust directory must be a real directory")
        info = trust_dir.stat()
        if self.require_root_owned_trust and os.name == "posix" and info.st_uid != 0:
            raise PermissionError("impact assessment trust directory must be root-owned")
        if stat.S_IMODE(info.st_mode) & 0o027:
            raise PermissionError("impact assessment trust directory permissions are too broad")
        verifier = self._verifier
        if verifier.is_symlink() or not verifier.is_file() or not os.access(verifier, os.X_OK):
            raise PermissionError("fixed impact assessment verifier is unavailable")
        verifier_info = verifier.stat()
        if self.require_root_owned_trust and os.name == "posix" and verifier_info.st_uid != 0:
            raise PermissionError("impact assessment verifier must be root-owned")
        if stat.S_IMODE(verifier_info.st_mode) & 0o022:
            raise PermissionError("impact assessment verifier must not be group/other writable")
        with tempfile.TemporaryDirectory(prefix="a2z-impact-assessment-") as directory:
            path = Path(directory) / "assessment.json"
            path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
            path.chmod(0o600)
            environment = {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "A2Z_IMPACT_TRUST_DIR": str(trust_dir),
            }
            try:
                result = subprocess.run(
                    ["/bin/bash", str(verifier), str(path)], check=False,
                    capture_output=True, text=True, timeout=self.timeout_seconds,
                    close_fds=True, env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("impact assessment signature verification failed closed") from exc
        if result.returncode != 0:
            raise PermissionError("impact assessment signature verification failed")


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"impact assessment {field} must be ISO 8601")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"impact assessment {field} must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"impact assessment {field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps({"domain": DOMAIN, "assessment": value}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def impact_assessment_digest(envelope: dict[str, Any]) -> str:
    """Return the digest of the domain-separated payload carried by an envelope."""
    if not isinstance(envelope, dict) or set(envelope) != {"assessment", "signature"} or not isinstance(envelope["assessment"], dict):
        raise ValueError("impact assessment envelope is malformed")
    payload = _canonical(envelope["assessment"])
    if len(payload) > MAX_ASSESSMENT_BYTES:
        raise ValueError("impact assessment exceeds 32 KiB")
    return hashlib.sha256(payload).hexdigest()
