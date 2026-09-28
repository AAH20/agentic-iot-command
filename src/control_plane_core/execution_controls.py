from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Protocol


CONTROL_SCHEMA = "a2z-execution-control-v1"
MAX_CONTROL_BYTES = 4096


class ExecutionControl(Protocol):
    def assert_enabled(self) -> str: ...


class RootManagedExecutionControl:
    """Host-admin kill switch; missing, stale, or malformed state denies grants."""

    def __init__(self, path: str | Path, *, max_enable_ttl_seconds: int = 3600,
                 require_root_owned: bool = True) -> None:
        self.path = Path(path).expanduser()
        if not 60 <= max_enable_ttl_seconds <= 3600:
            raise ValueError("execution-control enable TTL must be between 60 and 3600 seconds")
        self.max_enable_ttl_seconds = max_enable_ttl_seconds
        self.require_root_owned = require_root_owned

    def assert_enabled(self) -> str:
        path = self.path
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CONTROL_BYTES:
            raise PermissionError("root-managed execution kill-switch file is missing or invalid")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("execution kill-switch must be a regular file")
        if self.require_root_owned and os.name == "posix" and info.st_uid != 0:
            raise PermissionError("execution kill-switch file must be root-owned")
        if stat.S_IMODE(info.st_mode) & 0o027:
            raise PermissionError("execution kill-switch file must not be group-writable or accessible to other users")
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("execution kill-switch parent must be a real directory")
        parent_info = parent.stat()
        if self.require_root_owned and os.name == "posix" and parent_info.st_uid != 0:
            raise PermissionError("execution kill-switch parent must be root-owned")
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("execution kill-switch parent must not be group/other writable")
        try:
            control = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PermissionError("execution kill-switch file is malformed") from exc
        expected = {"schema_version", "execution_enabled", "issued_at", "expires_at", "reason"}
        if not isinstance(control, dict) or set(control) != expected or control.get("schema_version") != CONTROL_SCHEMA:
            raise PermissionError("execution kill-switch fields do not match the contract")
        if not isinstance(control["execution_enabled"], bool) or not isinstance(control["reason"], str):
            raise PermissionError("execution kill-switch values are invalid")
        if not control["execution_enabled"]:
            raise PermissionError("global execution kill switch is engaged")
        issued = _timestamp(control["issued_at"])
        expires = _timestamp(control["expires_at"])
        now = dt.datetime.now(dt.timezone.utc)
        if (issued > now + dt.timedelta(seconds=15) or expires <= now or expires <= issued
                or (expires - issued).total_seconds() > self.max_enable_ttl_seconds):
            raise PermissionError("execution kill-switch enablement is expired or outside its short TTL")
        return hashlib.sha256(_canonical(control)).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate execution-control JSON key")
        result[key] = value
    return result


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise PermissionError("execution kill-switch timestamps must be ISO 8601")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PermissionError("execution kill-switch timestamps must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise PermissionError("execution kill-switch timestamps must include timezone")
    return parsed.astimezone(dt.timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
