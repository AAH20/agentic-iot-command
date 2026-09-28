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

from .autonomy import AutonomyProfile, AutonomyRule, MaintenanceWindow


PROFILE_DOMAIN = "a2z.autonomy-profile.v1"
MAX_PROFILE_BYTES = 1024 * 1024
MAX_PROFILE_LIFETIME = dt.timedelta(days=30)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_payload(profile_data: dict[str, Any]) -> bytes:
    return json.dumps(
        {"domain": PROFILE_DOMAIN, "profile": profile_data},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


class AutonomyProfileVerifier(Protocol):
    def verify(self, signed_envelope: dict[str, Any]) -> str: ...


class Ed25519AutonomyProfileVerifier:
    """Verify standing-policy signatures against a dedicated public-key trust directory."""

    def __init__(self, trust_dir: str | Path | None = None, *, verifier_bin: str | None = None, timeout_seconds: int = 10, require_root_owned_trust: bool = True) -> None:
        root = Path(__file__).resolve().parents[2]
        self.trust_dir = Path(trust_dir or os.environ.get("A2Z_AUTONOMY_TRUST_DIR", "")).expanduser()
        self.verifier_bin = verifier_bin or str(root / "scripts" / "verify-autonomy-profile.sh")
        self.timeout_seconds = timeout_seconds
        self.require_root_owned_trust = require_root_owned_trust

    def verify(self, signed_envelope: dict[str, Any]) -> str:
        if self.trust_dir.is_symlink() or not self.trust_dir.is_dir():
            raise PermissionError("A2Z_AUTONOMY_TRUST_DIR must be a real policy public-key trust directory")
        trust_stat = self.trust_dir.stat()
        trust_mode = stat.S_IMODE(trust_stat.st_mode)
        if self.require_root_owned_trust and os.name == "posix" and trust_stat.st_uid != 0:
            raise PermissionError("autonomy policy trust directory must be root-owned")
        if trust_mode & 0o027:
            raise PermissionError("autonomy policy trust directory must not be group-writable or accessible by other users")
        payload = signed_envelope.get("profile")
        if not isinstance(payload, dict):
            raise ValueError("signed autonomy envelope has no profile object")
        canonical = _canonical_payload(payload)
        digest = hashlib.sha256(canonical).hexdigest()
        verifier = Path(self.verifier_bin)
        if not verifier.is_file():
            raise PermissionError("autonomy policy signature verifier is unavailable")
        with tempfile.TemporaryDirectory(prefix="a2z-autonomy-profile-") as tmp:
            record_path = Path(tmp) / "signed-profile.json"
            record_path.write_text(json.dumps(signed_envelope, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            record_path.chmod(0o600)
            try:
                result = subprocess.run(
                    ["/bin/bash", str(verifier), str(record_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    close_fds=True,
                    env={**os.environ, "A2Z_AUTONOMY_TRUST_DIR": str(self.trust_dir)},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PermissionError("autonomy profile signature verification failed closed") from exc
        if result.returncode != 0:
            raise PermissionError("autonomy profile signature verification failed")
        return digest


def load_signed_autonomy_profile(
    path: str | Path,
    *,
    verifier: AutonomyProfileVerifier | None = None,
    now: dt.datetime | None = None,
) -> AutonomyProfile:
    """Load a strict, domain-separated signed policy; never trust a JSON verified flag."""
    profile_path = Path(path).expanduser()
    if profile_path.is_symlink() or not profile_path.is_file():
        raise PermissionError("autonomy profile must be a regular non-symlink file")
    if profile_path.stat().st_size > MAX_PROFILE_BYTES:
        raise ValueError("autonomy profile exceeds the size limit")
    if profile_path.stat().st_mode & 0o022:
        raise PermissionError("autonomy profile must not be writable by group or other users")
    try:
        envelope = json.loads(profile_path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("autonomy profile is not valid UTF-8 JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"profile", "signature"}:
        raise ValueError("signed autonomy envelope must contain exactly profile and signature")
    profile_data = envelope["profile"]
    signature = envelope["signature"]
    if not isinstance(profile_data, dict) or not isinstance(signature, dict):
        raise ValueError("profile and signature must be JSON objects")
    if set(signature) != {"algorithm", "key_id", "signature_base64"}:
        raise ValueError("autonomy signature fields do not match the contract")
    if signature.get("algorithm") != "ed25519" or not re.fullmatch(r"[A-Za-z0-9._-]+", str(signature.get("key_id", ""))):
        raise ValueError("autonomy policy must use an identified Ed25519 signing key")
    try:
        base64.b64decode(signature["signature_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("autonomy signature encoding is invalid") from exc

    expected_fields = {
        "schema_version", "profile_id", "tenant_id", "enabled", "issued_at", "expires_at",
        "max_concurrency", "max_total_targets", "max_affected_resources",
        "max_estimated_cost_microusd", "rules", "denied_actions", "defaults",
    }
    fields_with_windows = expected_fields | {"maintenance_windows"}
    if set(profile_data) not in (expected_fields, fields_with_windows) or profile_data.get("schema_version") != "autonomy-profile-v1":
        raise ValueError("autonomy profile fields do not match autonomy-profile-v1")
    if not all(isinstance(profile_data.get(key), str) and profile_data[key].strip() for key in ("profile_id", "tenant_id")):
        raise ValueError("profile_id and tenant_id must be non-empty strings")
    if not isinstance(profile_data.get("enabled"), bool):
        raise ValueError("profile enabled must be boolean")
    issued_at = _parse_timestamp(profile_data.get("issued_at"), "issued_at")
    expires_at = _parse_timestamp(profile_data.get("expires_at"), "expires_at")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise ValueError("loader clock must include a timezone")
    if issued_at > current or expires_at <= current or expires_at <= issued_at:
        raise PermissionError("autonomy profile is not currently valid")
    if expires_at - issued_at > MAX_PROFILE_LIFETIME:
        raise PermissionError("autonomy profile lifetime exceeds 30 days")

    max_concurrency = _bounded_int(profile_data.get("max_concurrency"), "max_concurrency", 1, 32)
    max_total_targets = _bounded_int(profile_data.get("max_total_targets"), "max_total_targets", 1, 500)
    max_affected_resources = _bounded_int(profile_data.get("max_affected_resources"), "max_affected_resources", 1, 1_000_000)
    max_estimated_cost_microusd = _bounded_int(profile_data.get("max_estimated_cost_microusd"), "max_estimated_cost_microusd", 0, 10**12)
    defaults = profile_data.get("defaults")
    required_defaults = {
        "unknown_action": "deny",
        "non_allowlisted_action": "approval_required",
        "high_impact_action": "approval_required",
        "production_action": "approval_required",
        "regulated_action": "deny",
    }
    if defaults != required_defaults:
        raise ValueError("autonomy default decisions must preserve the fail-closed contract")

    rules_data = profile_data.get("rules")
    if not isinstance(rules_data, list) or len(rules_data) > 500:
        raise ValueError("rules must be a bounded array")
    rules = tuple(_parse_rule(item) for item in rules_data)
    if len({rule.action_id for rule in rules}) != len(rules):
        raise ValueError("only one autonomy rule per action_id is permitted")
    windows_data = profile_data.get("maintenance_windows", [])
    if not isinstance(windows_data, list) or len(windows_data) > 100:
        raise ValueError("maintenance_windows must be a bounded array")
    windows = tuple(_parse_window(item, issued_at=issued_at, expires_at=expires_at)
                    for item in windows_data)
    if len({window.window_id for window in windows}) != len(windows):
        raise ValueError("maintenance window IDs must be unique")
    denied_data = profile_data.get("denied_actions")
    if not isinstance(denied_data, list) or any(not isinstance(item, str) or not item for item in denied_data):
        raise ValueError("denied_actions must be an array of non-empty strings")
    if len(set(denied_data)) != len(denied_data):
        raise ValueError("denied_actions must be unique")

    # Cryptographic verification occurs only after the signed bytes have passed
    # strict structure and time-bound checks.
    policy_digest = (verifier or Ed25519AutonomyProfileVerifier()).verify(envelope)
    if not re.fullmatch(r"[0-9a-f]{64}", policy_digest):
        raise PermissionError("signature verifier returned an invalid policy digest")
    return AutonomyProfile(
        profile_id=profile_data["profile_id"],
        tenant_id=profile_data["tenant_id"],
        expires_at=expires_at,
        rules=rules,
        verified_signature=True,
        revoked=False,
        max_concurrency=max_concurrency,
        max_total_targets=max_total_targets,
        denied_actions=tuple(denied_data),
        enabled=profile_data["enabled"],
        policy_digest=policy_digest,
        max_affected_resources=max_affected_resources,
        max_estimated_cost_microusd=max_estimated_cost_microusd,
        maintenance_windows=windows,
        signed_record=envelope,
    )


def load_signed_autonomy_profile_record(
    signed_envelope: dict[str, Any],
    *,
    verifier: AutonomyProfileVerifier,
    now: dt.datetime | None = None,
) -> AutonomyProfile:
    """Strictly parse and reverify a retained profile envelope from the journal."""
    try:
        encoded = json.dumps(
            signed_envelope, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("retained autonomy profile is not strict JSON") from exc
    if len(encoded) > MAX_PROFILE_BYTES:
        raise ValueError("retained autonomy profile exceeds the size limit")
    with tempfile.TemporaryDirectory(prefix="a2z-autonomy-record-") as directory:
        record_path = Path(directory) / "signed-profile.json"
        record_path.write_bytes(encoded + b"\n")
        record_path.chmod(0o600)
        return load_signed_autonomy_profile(record_path, verifier=verifier, now=now)


def _parse_timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if result.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return result.astimezone(dt.timezone.utc)


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _parse_rule(value: Any) -> AutonomyRule:
    fields = {
        "action_id", "target_ids", "environments", "max_targets_per_run",
        "max_batch_size", "max_affected_resources", "max_estimated_cost_microusd", "enabled",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("autonomy rule fields do not match the contract")
    action_id = value["action_id"]
    targets = value["target_ids"]
    environments = value["environments"]
    if not isinstance(action_id, str) or not action_id.strip() or action_id in {"*", "shell.exec", "command.run"}:
        raise ValueError("autonomy rule action_id is invalid or generic")
    if not isinstance(targets, list) or not targets or len(targets) > 500 or any(not isinstance(t, str) or not t.strip() for t in targets):
        raise ValueError("autonomy rule must contain exact non-empty target IDs")
    if len(set(targets)) != len(targets):
        raise ValueError("autonomy rule targets must be unique")
    allowed_envs = {"lab", "development", "staging"}
    if not isinstance(environments, list) or not environments or any(env not in allowed_envs for env in environments):
        raise ValueError("autonomy rules may target only lab, development, or staging")
    if len(set(environments)) != len(environments):
        raise ValueError("autonomy rule environments must be unique")
    if not isinstance(value["enabled"], bool):
        raise ValueError("autonomy rule enabled must be boolean")
    return AutonomyRule(
        action_id=action_id,
        target_ids=tuple(targets),
        environments=tuple(environments),
        max_targets_per_run=_bounded_int(value["max_targets_per_run"], "max_targets_per_run", 1, 500),
        max_batch_size=_bounded_int(value["max_batch_size"], "max_batch_size", 1, 32),
        enabled=value["enabled"],
        max_affected_resources=_bounded_int(value["max_affected_resources"], "max_affected_resources", 1, 100_000),
        max_estimated_cost_microusd=_bounded_int(value["max_estimated_cost_microusd"], "max_estimated_cost_microusd", 0, 10**12),
    )


def _parse_window(value: Any, *, issued_at: dt.datetime, expires_at: dt.datetime) -> MaintenanceWindow:
    fields = {"window_id", "action_id", "target_ids", "environments", "starts_at", "ends_at"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("maintenance-window fields do not match the contract")
    window_id, action_id = value["window_id"], value["action_id"]
    if (not isinstance(window_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", window_id)
            or not isinstance(action_id, str) or not action_id.strip()
            or action_id in {"*", "shell.exec", "command.run"}):
        raise ValueError("maintenance-window ID or action is invalid")
    targets, environments = value["target_ids"], value["environments"]
    if (not isinstance(targets, list) or not targets or len(targets) > 500
            or any(not isinstance(item, str) or not item.strip() or item == "*" for item in targets)
            or len(set(targets)) != len(targets)):
        raise ValueError("maintenance window must list unique exact target IDs")
    allowed = {"lab", "development", "staging"}
    if (not isinstance(environments, list) or not environments
            or any(not isinstance(item, str) or item not in allowed for item in environments)
            or len(set(environments)) != len(environments)):
        raise ValueError("maintenance window environments are invalid")
    starts_at = _parse_timestamp(value["starts_at"], "maintenance window starts_at")
    ends_at = _parse_timestamp(value["ends_at"], "maintenance window ends_at")
    if (starts_at < issued_at or ends_at > expires_at or ends_at <= starts_at
            or ends_at - starts_at > dt.timedelta(hours=8)):
        raise PermissionError("maintenance window must be within the signed profile and at most 8 hours")
    return MaintenanceWindow(
        window_id=window_id, action_id=action_id, target_ids=tuple(targets),
        environments=tuple(environments), starts_at=starts_at, ends_at=ends_at,
    )
