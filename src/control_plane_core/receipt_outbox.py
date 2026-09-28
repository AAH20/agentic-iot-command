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


class RunnerReceiptOutbox:
    """Owner-only durable spool for signed receipts awaiting journal acknowledgment."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().absolute()
        parent = self.path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("receipt outbox parent must be an existing real directory")
        parent_info = parent.stat()
        if (parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise PermissionError("receipt outbox parent must belong to the runner and not be group/other writable")
        for ancestor in parent.parents:
            info = ancestor.lstat()
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid != 0:
                    raise PermissionError("receipt outbox path may traverse only root-owned symlinks")
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise PermissionError("receipt outbox ancestors must be directories")
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022 and not mode & stat.S_ISVTX:
                raise PermissionError("receipt outbox path traverses a writable non-sticky directory")
        if self.path.is_symlink():
            raise PermissionError("receipt outbox database may not be a symlink")
        self._db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        os.chmod(self.path, 0o600)
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                lease_token TEXT,
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
            raise PermissionError("receipt outbox must be a regular runner-owned mode-0600 file")

    def close(self) -> None:
        self._db.close()

    def put(self, *, task_id: str, lease_generation: int, lease_token: str,
            envelope: dict[str, Any]) -> None:
        try:
            task_id = str(UUID(task_id))
            receipt_id = str(UUID(envelope["attestation"]["receipt_id"]))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError("outbox requires UUID task and receipt IDs") from exc
        if (isinstance(lease_generation, bool) or not isinstance(lease_generation, int)
                or lease_generation < 1):
            raise ValueError("outbox lease_generation must be positive")
        if not isinstance(lease_token, str) or not lease_token or len(lease_token) > 512:
            raise ValueError("outbox lease token must be a bounded non-empty string")
        if (not isinstance(envelope, dict) or set(envelope) != {"attestation", "signature"}
                or not isinstance(envelope["attestation"], dict)
                or not isinstance(envelope["signature"], dict)
                or envelope["attestation"].get("task_id") != task_id
                or isinstance(envelope["attestation"].get("lease_generation"), bool)
                or not isinstance(envelope["attestation"].get("lease_generation"), int)
                or envelope["attestation"].get("lease_generation") != lease_generation):
            raise ValueError("outbox envelope is malformed or belongs to another task")
        serialized = _canonical(envelope)
        if len(serialized.encode("utf-8")) > 64 * 1024:
            raise ValueError("outbox receipt exceeds 64 KiB")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing = self._db.execute(
                "SELECT receipt_id,envelope_json,lease_token FROM receipts WHERE task_id=? AND lease_generation=?",
                (task_id, lease_generation),
            ).fetchone()
            if existing:
                if (existing[0] != receipt_id or existing[1] != serialized
                        or existing[2] not in (lease_token, None)):
                    raise PermissionError("a different receipt already exists for this task lease")
                self._db.execute("COMMIT")
                return
            self._db.execute(
                "INSERT INTO receipts (receipt_id,task_id,lease_generation,envelope_json,lease_token,state,created_at) VALUES (?,?,?,?,?,'pending',?)",
                (receipt_id, task_id, lease_generation, serialized, lease_token,
                 datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")),
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def pending(self, *, limit: int = 10) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("outbox pending page size must be between 1 and 100")
        rows = self._db.execute(
            "SELECT receipt_id,task_id,lease_generation,envelope_json,lease_token,created_at "
            "FROM receipts WHERE state='pending' ORDER BY created_at,receipt_id LIMIT ?", (limit,),
        ).fetchall()
        return [{
            "receipt_id": row[0], "task_id": row[1], "lease_generation": row[2],
            "envelope": json.loads(row[3]), "lease_token": row[4], "created_at": row[5],
        } for row in rows]

    def mark_delivered(self, *, receipt_id: str) -> None:
        try:
            receipt_id = str(UUID(receipt_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("receipt_id must be a UUID") from exc
        cursor = self._db.execute(
            "UPDATE receipts SET state='delivered',lease_token=NULL,delivered_at=? "
            "WHERE receipt_id=? AND state='pending'",
            (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), receipt_id),
        )
        if cursor.rowcount != 1:
            state = self._db.execute("SELECT state FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
            if not state or state[0] != "delivered":
                raise KeyError("pending receipt was not found in the outbox")
