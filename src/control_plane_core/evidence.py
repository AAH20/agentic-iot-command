from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class EvidenceEnvelope:
    envelope_id: UUID
    tenant_id: str
    schema_version: str
    event_type: str
    collected_at: str
    collector: str
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        payload = copy.deepcopy(self.payload)
        return {
            "envelope_id": str(self.envelope_id),
            "tenant_id": self.tenant_id,
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "integrity": {"algorithm": "sha256", "payload_sha256": _digest(payload)},
            "payload": payload,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    record_id: UUID
    tenant_id: str
    sequence: int
    appended_at: str
    previous_record_sha256: str | None
    evidence_sha256: str
    evidence: dict[str, Any]
    record_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_version": "ledger-record-v1",
            "record_id": str(self.record_id),
            "tenant_id": self.tenant_id,
            "sequence": self.sequence,
            "appended_at": self.appended_at,
            "previous_record_sha256": self.previous_record_sha256,
            "evidence_sha256": self.evidence_sha256,
            "evidence": copy.deepcopy(self.evidence),
            "record_sha256": self.record_sha256,
        }


class EvidenceLedger:
    """Tenant-partitioned append-only evidence chain, optionally file-backed.

    This is the local service boundary for the architecture's evidence ledger.
    The file adapter is a local JSONL store, not a durable database, signer,
    exporter, or approval system. Each tenant has an independent chain and
    query results are defensive copies.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._records: dict[str, list[EvidenceRecord]] = {}
        self._lock = threading.RLock()
        self.path = Path(path).expanduser() if path is not None else None
        if self.path is not None:
            self.path = self.path.absolute()
            if not self.path.parent.is_dir():
                raise ValueError("evidence ledger parent directory must already exist")
            with self._file_access(exclusive=False) as stream:
                self._records = self._read_stream(stream)

    def append(self, envelope: EvidenceEnvelope) -> EvidenceRecord:
        self._validate_envelope(envelope)
        with self._lock:
            if self.path is None:
                return self._append_to_cache(envelope)
            with self._file_access(exclusive=True) as stream:
                self._records = self._read_stream(stream)
                record = self._append_to_cache(envelope)
                stream.seek(0, os.SEEK_END)
                stream.write(json.dumps(record.as_dict(), sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                return copy.deepcopy(record)

    def record(self, *, tenant_id: str, event_type: str, collector: str, payload: dict[str, Any], collected_at: str | None = None) -> EvidenceRecord:
        return self.append(
            EvidenceEnvelope(
                envelope_id=uuid4(),
                tenant_id=tenant_id,
                schema_version="evidence-envelope-v1",
                event_type=event_type,
                collected_at=collected_at or _now(),
                collector=collector,
                payload=payload,
            )
        )

    def list(self, *, tenant_id: str, event_type: str | None = None) -> tuple[EvidenceRecord, ...]:
        self._require_tenant(tenant_id)
        with self._lock:
            if self.path is not None:
                with self._file_access(exclusive=False) as stream:
                    self._records = self._read_stream(stream)
            records = self._records.get(tenant_id, [])
            if event_type is not None and not event_type.strip():
                raise ValueError("event_type filter must be non-empty")
            return tuple(copy.deepcopy(record) for record in records if event_type is None or record.evidence["event_type"] == event_type)

    def verify(self, *, tenant_id: str) -> dict[str, Any]:
        self._require_tenant(tenant_id)
        with self._lock:
            if self.path is not None:
                with self._file_access(exclusive=False) as stream:
                    self._records = self._read_stream(stream)
            return self.verify_records(tenant_id, self._records.get(tenant_id, []))

    @staticmethod
    def verify_records(tenant_id: str, records: list[EvidenceRecord]) -> dict[str, Any]:
        if not tenant_id.strip():
            raise ValueError("tenant_id is required")
        previous: str | None = None
        for expected_sequence, record in enumerate(records, start=1):
            serialized = record.as_dict()
            if record.tenant_id != tenant_id or record.sequence != expected_sequence or record.previous_record_sha256 != previous:
                raise ValueError("evidence chain sequence, tenant, or previous link is invalid")
            if _digest(record.evidence) != record.evidence_sha256:
                raise ValueError("evidence hash is invalid")
            unsigned = dict(serialized)
            unsigned.pop("record_sha256")
            if _digest(unsigned) != record.record_sha256:
                raise ValueError("record hash is invalid")
            previous = record.record_sha256
        return {"tenant_id": tenant_id, "records": len(records), "last_record_sha256": previous, "execution_permitted": False}

    @staticmethod
    def _validate_envelope(envelope: EvidenceEnvelope) -> None:
        if not envelope.tenant_id.strip() or not envelope.event_type.strip() or not envelope.collector.strip():
            raise ValueError("tenant, event type, and collector are required")
        if envelope.schema_version != "evidence-envelope-v1":
            raise ValueError("unsupported evidence envelope schema")
        if not isinstance(envelope.payload, dict):
            raise ValueError("evidence payload must be an object")
        payload_tenant = envelope.payload.get("tenant_id")
        if payload_tenant is not None and payload_tenant != envelope.tenant_id:
            raise PermissionError("evidence payload crosses tenant boundary")

    def _require_tenant(self, tenant_id: str) -> None:
        if not tenant_id.strip():
            raise ValueError("tenant_id is required")

    def _append_to_cache(self, envelope: EvidenceEnvelope) -> EvidenceRecord:
        tenant_records = self._records.setdefault(envelope.tenant_id, [])
        previous = tenant_records[-1].record_sha256 if tenant_records else None
        record = self._build_record(envelope, len(tenant_records) + 1, previous)
        tenant_records.append(record)
        return copy.deepcopy(record)

    @staticmethod
    def _build_record(envelope: EvidenceEnvelope, sequence: int, previous: str | None) -> EvidenceRecord:
        evidence = envelope.as_dict()
        evidence_hash = _digest(evidence)
        appended_at = _now()
        unsigned = {
            "record_version": "ledger-record-v1",
            "record_id": str(uuid4()),
            "tenant_id": envelope.tenant_id,
            "sequence": sequence,
            "appended_at": appended_at,
            "previous_record_sha256": previous,
            "evidence_sha256": evidence_hash,
            "evidence": evidence,
        }
        return EvidenceRecord(
            record_id=UUID(unsigned["record_id"]),
            tenant_id=envelope.tenant_id,
            sequence=sequence,
            appended_at=appended_at,
            previous_record_sha256=previous,
            evidence_sha256=evidence_hash,
            evidence=evidence,
            record_sha256=_digest(unsigned),
        )

    @staticmethod
    def record_from_dict(serialized: dict[str, Any]) -> EvidenceRecord:
        try:
            return EvidenceRecord(
                record_id=UUID(serialized["record_id"]),
                tenant_id=str(serialized["tenant_id"]),
                sequence=int(serialized["sequence"]),
                appended_at=str(serialized["appended_at"]),
                previous_record_sha256=serialized.get("previous_record_sha256"),
                evidence_sha256=str(serialized["evidence_sha256"]),
                evidence=serialized["evidence"],
                record_sha256=str(serialized["record_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed persisted evidence record") from exc

    @contextmanager
    def _file_access(self, *, exclusive: bool):
        if self.path is None:
            raise RuntimeError("file-backed ledger is not configured")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.path, flags, 0o600)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) & 0o077:
            os.close(descriptor)
            raise PermissionError("evidence ledger must be a regular file with owner-only permissions")
        stream = os.fdopen(descriptor, "r+", encoding="utf-8")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield stream
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()

    @staticmethod
    def _read_stream(stream) -> dict[str, list[EvidenceRecord]]:
        stream.seek(0)
        records: dict[str, list[EvidenceRecord]] = {}
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise ValueError(f"ledger line {line_number} is blank")
            serialized = json.loads(line)
            if not isinstance(serialized, dict):
                raise ValueError(f"ledger line {line_number} must be an object")
            if serialized.get("record_version") != "ledger-record-v1":
                raise ValueError(f"ledger line {line_number} has an unsupported record version")
            tenant_id = serialized.get("tenant_id")
            if not isinstance(tenant_id, str) or not tenant_id.strip():
                raise ValueError(f"ledger line {line_number} has no tenant scope")
            evidence = serialized.get("evidence")
            if not isinstance(evidence, dict):
                raise ValueError(f"ledger line {line_number} has no evidence envelope")
            tenant_records = records.setdefault(tenant_id, [])
            previous = tenant_records[-1].record_sha256 if tenant_records else None
            sequence = len(tenant_records) + 1
            if serialized.get("sequence") != sequence or serialized.get("previous_record_sha256") != previous:
                raise ValueError(f"ledger line {line_number} has an invalid tenant chain link")
            if serialized.get("evidence_sha256") != _digest(evidence):
                raise ValueError(f"ledger line {line_number} has an invalid evidence hash")
            unsigned = dict(serialized)
            stored_hash = unsigned.pop("record_sha256", None)
            if not isinstance(stored_hash, str) or stored_hash != _digest(unsigned):
                raise ValueError(f"ledger line {line_number} has an invalid record hash")
            if evidence.get("tenant_id") != tenant_id:
                raise ValueError(f"ledger line {line_number} evidence tenant does not match record")
            if evidence.get("schema_version") != "evidence-envelope-v1":
                raise ValueError(f"ledger line {line_number} has an unsupported evidence schema")
            payload = evidence.get("payload")
            integrity = evidence.get("integrity")
            if (
                not isinstance(payload, dict)
                or not isinstance(integrity, dict)
                or integrity.get("algorithm") != "sha256"
                or integrity.get("payload_sha256") != _digest(payload)
            ):
                raise ValueError(f"ledger line {line_number} has invalid payload integrity")
            try:
                record = EvidenceRecord(
                    record_id=UUID(serialized["record_id"]),
                    tenant_id=tenant_id,
                    sequence=sequence,
                    appended_at=serialized["appended_at"],
                    previous_record_sha256=previous,
                    evidence_sha256=serialized["evidence_sha256"],
                    evidence=evidence,
                    record_sha256=stored_hash,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"ledger line {line_number} has malformed record fields") from exc
            tenant_records.append(record)
        return records
