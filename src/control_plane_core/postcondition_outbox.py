from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class PostconditionAttestationOutbox:
    """Owner-only durable spool that retries the exact signed observation, never re-signs it."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().absolute()
        parent = self.path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("postcondition outbox parent must be an existing real directory")
        parent_info = parent.stat()
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("postcondition outbox parent must belong to the verifier and not be group/other writable")
        for ancestor in parent.parents:
            info = ancestor.lstat()
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid != 0:
                    raise PermissionError("postcondition outbox path may traverse only root-owned symlinks")
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise PermissionError("postcondition outbox ancestors must be directories")
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022 and not mode & stat.S_ISVTX:
                raise PermissionError("postcondition outbox path traverses a writable non-sticky directory")
        if self.path.is_symlink():
            raise PermissionError("postcondition outbox database may not be a symlink")
        self._db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        os.chmod(self.path, 0o600)
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS attestations (
                verification_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending','delivered')),
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                UNIQUE (task_id,lease_generation)
            )
        """)
        info = self.path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            self._db.close()
            raise PermissionError("postcondition outbox must be a regular verifier-owned mode-0600 file")

    def close(self) -> None:
        self._db.close()

    def put(self, *, envelope: dict[str, Any]) -> None:
        attestation = _validate_envelope(envelope)
        serialized = _canonical(envelope)
        if len(serialized.encode("utf-8")) > 64 * 1024:
            raise ValueError("postcondition envelope exceeds 64 KiB")
        task_id = str(UUID(attestation["task_id"]))
        verification_id = str(UUID(attestation["verification_id"]))
        generation = attestation["lease_generation"]
        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing = self._db.execute(
                "SELECT verification_id,tenant_id,envelope_json,state FROM attestations "
                "WHERE task_id=? AND lease_generation=?", (task_id, generation),
            ).fetchone()
            if existing:
                if (existing[0] != verification_id or existing[1] != attestation["tenant_id"]
                        or existing[2] != serialized):
                    raise PermissionError("a different signed postcondition already exists for this task lease")
                self._db.execute("COMMIT")
                return
            pending = self._db.execute(
                "SELECT verification_id,lease_generation FROM attestations "
                "WHERE task_id=? AND state='pending'", (task_id,),
            ).fetchone()
            if pending:
                raise PermissionError("an earlier postcondition submission is still pending for this task")
            self._db.execute(
                "INSERT INTO attestations "
                "(verification_id,task_id,tenant_id,lease_generation,envelope_json,state,created_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (verification_id, task_id, attestation["tenant_id"], generation, serialized,
                 _now()),
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def pending_for_task(self, *, task_id: str) -> dict[str, Any] | None:
        try:
            task_id = str(UUID(task_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("task_id must be a UUID") from exc
        rows = self._db.execute(
            "SELECT verification_id,task_id,tenant_id,lease_generation,envelope_json,created_at "
            "FROM attestations WHERE task_id=? AND state='pending' ORDER BY created_at,verification_id LIMIT 2",
            (task_id,),
        ).fetchall()
        if len(rows) > 1:
            raise PermissionError("multiple pending postcondition attestations exist for one task")
        if not rows:
            return None
        row = rows[0]
        return {"verification_id": row[0], "task_id": row[1], "tenant_id": row[2],
                "lease_generation": row[3], "envelope": json.loads(row[4]), "created_at": row[5]}

    def pending(self, *, limit: int = 10) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("postcondition outbox page size must be between 1 and 100")
        rows = self._db.execute(
            "SELECT verification_id,task_id,tenant_id,lease_generation,envelope_json,created_at "
            "FROM attestations WHERE state='pending' ORDER BY created_at,verification_id LIMIT ?", (limit,),
        ).fetchall()
        return [{"verification_id": row[0], "task_id": row[1], "tenant_id": row[2],
                 "lease_generation": row[3], "envelope": json.loads(row[4]), "created_at": row[5]}
                for row in rows]

    def mark_delivered(self, *, verification_id: str) -> None:
        try:
            verification_id = str(UUID(verification_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("verification_id must be a UUID") from exc
        cursor = self._db.execute(
            "UPDATE attestations SET state='delivered',delivered_at=? "
            "WHERE verification_id=? AND state='pending'", (_now(), verification_id),
        )
        if cursor.rowcount != 1:
            state = self._db.execute(
                "SELECT state FROM attestations WHERE verification_id=?", (verification_id,),
            ).fetchone()
            if not state or state[0] != "delivered":
                raise KeyError("pending postcondition attestation was not found in the outbox")


def _validate_envelope(envelope: Any) -> dict[str, Any]:
    if (not isinstance(envelope, dict) or set(envelope) != {"attestation", "signature"}
            or not isinstance(envelope["attestation"], dict) or not isinstance(envelope["signature"], dict)):
        raise ValueError("outbox requires a signed postcondition envelope")
    body, signature = envelope["attestation"], envelope["signature"]
    for field in ("task_id", "verification_id"):
        try:
            UUID(body[field])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError(f"postcondition outbox requires a UUID {field}") from exc
    if (not isinstance(body.get("tenant_id"), str) or not body["tenant_id"].strip()
            or isinstance(body.get("lease_generation"), bool)
            or not isinstance(body.get("lease_generation"), int) or body["lease_generation"] < 1):
        raise ValueError("postcondition envelope has invalid tenant or lease generation")
    if (signature.get("algorithm") != "ed25519" or not isinstance(signature.get("key_id"), str)
            or not isinstance(signature.get("signature_base64"), str)):
        raise ValueError("postcondition envelope signature metadata is invalid")
    return body


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
