#!/usr/bin/env python3
"""Append and verify local hash-chained evidence records."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import sys
import uuid
from typing import Any, TextIO


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate_evidence(evidence: dict[str, Any]) -> str:
    required = ("envelope_id", "tenant_id", "schema_version", "event_type", "collected_at", "collector", "integrity", "payload")
    missing = [key for key in required if key not in evidence]
    if missing:
        raise ValueError(f"evidence envelope missing {missing}")
    if not isinstance(evidence["tenant_id"], str) or not evidence["tenant_id"].strip():
        raise ValueError("evidence tenant_id must be a non-empty string")
    if evidence["schema_version"] != "evidence-envelope-v1":
        raise ValueError("unsupported evidence envelope schema")
    if not isinstance(evidence["payload"], dict):
        raise ValueError("evidence payload must be an object")
    integrity = evidence["integrity"]
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise ValueError("evidence envelope must use sha256 payload integrity")
    payload_hash = digest(evidence["payload"])
    if integrity.get("payload_sha256") != payload_hash:
        raise ValueError("evidence payload hash does not match its integrity field")
    return digest(evidence)


def verify_stream(stream: TextIO) -> tuple[int, str | None]:
    previous_by_tenant: dict[str, str] = {}
    sequence_by_tenant: dict[str, int] = {}
    count = 0
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            raise ValueError(f"ledger line {line_number} is blank")
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"ledger line {line_number} is not an object")
        if record.get("record_version") != "ledger-record-v1":
            raise ValueError(f"ledger line {line_number} has an unsupported record version")
        tenant_id = record.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError(f"ledger line {line_number} has no tenant scope")
        expected_previous = previous_by_tenant.get(tenant_id)
        if record.get("previous_record_sha256") != expected_previous:
            raise ValueError(f"ledger line {line_number} has an invalid tenant previous-record link")
        expected_sequence = sequence_by_tenant.get(tenant_id, 0) + 1
        if record.get("sequence") != expected_sequence:
            raise ValueError(f"ledger line {line_number} has an invalid tenant sequence")
        evidence = record.get("evidence", {})
        evidence_hash = validate_evidence(evidence)
        if evidence.get("tenant_id") != tenant_id:
            raise ValueError(f"ledger line {line_number} evidence tenant does not match record")
        if record.get("evidence_sha256") != evidence_hash:
            raise ValueError(f"ledger line {line_number} has an invalid evidence hash")
        stored_hash = record.get("record_sha256")
        unsigned = dict(record)
        unsigned.pop("record_sha256", None)
        if not isinstance(stored_hash, str) or stored_hash != digest(unsigned):
            raise ValueError(f"ledger line {line_number} has an invalid record hash")
        previous_by_tenant[tenant_id] = stored_hash
        sequence_by_tenant[tenant_id] = expected_sequence
        count += 1
    last_hash = digest(previous_by_tenant) if previous_by_tenant else None
    return count, last_hash


def append_record(evidence_path: pathlib.Path, ledger_path: pathlib.Path) -> None:
    evidence = load_json(evidence_path)
    evidence_hash = validate_evidence(evidence)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(ledger_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) & 0o077:
        os.close(fd)
        raise ValueError("ledger must be a regular file with owner-only permissions")
    with os.fdopen(fd, "r+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        stream.seek(0)
        count, _ = verify_stream(stream)
        stream.seek(0)
        previous_by_tenant: dict[str, str] = {}
        sequence_by_tenant: dict[str, int] = {}
        for line_number, line in enumerate(stream, start=1):
            existing = json.loads(line)
            tenant = existing["tenant_id"]
            previous_by_tenant[tenant] = existing["record_sha256"]
            sequence_by_tenant[tenant] = existing["sequence"]
        previous = previous_by_tenant.get(evidence["tenant_id"])
        sequence = sequence_by_tenant.get(evidence["tenant_id"], 0) + 1
        record: dict[str, Any] = {
            "record_version": "ledger-record-v1",
            "record_id": str(uuid.uuid4()),
            "tenant_id": evidence["tenant_id"],
            "sequence": sequence,
            "appended_at": now(),
            "previous_record_sha256": previous,
            "evidence_sha256": evidence_hash,
            "evidence": evidence,
        }
        record["record_sha256"] = digest(record)
        stream.seek(0, os.SEEK_END)
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    print(f"ALLOW: appended ledger record {record['record_id']} at tenant sequence {sequence} (global records: {count + 1})")
    print(f"record_sha256={record['record_sha256']}")


def verify_ledger(ledger_path: pathlib.Path) -> None:
    if not ledger_path.exists():
        raise ValueError(f"ledger does not exist: {ledger_path}")
    fd = os.open(ledger_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) & 0o077:
        os.close(fd)
        raise ValueError("ledger must be a regular file with owner-only permissions")
    with os.fdopen(fd, encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        try:
            count, digest_summary = verify_stream(stream)
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    print(f"ALLOW: verified {count} ledger records")
    if digest_summary:
        print(f"tenant_heads_sha256={digest_summary}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    append = subparsers.add_parser("append")
    append.add_argument("evidence")
    append.add_argument("ledger")
    verify = subparsers.add_parser("verify")
    verify.add_argument("ledger")
    args = parser.parse_args()
    try:
        if args.command == "append":
            append_record(pathlib.Path(args.evidence), pathlib.Path(args.ledger))
        else:
            verify_ledger(pathlib.Path(args.ledger))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BLOCK: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
