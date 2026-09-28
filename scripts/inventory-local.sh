#!/usr/bin/env bash
set -euo pipefail

OUTPUT="${1:?usage: inventory-local.sh <output.json>}"
TENANT_ID="${2:-local}"
mkdir -p "$(dirname "$OUTPUT")"

python3 - "$OUTPUT" "$TENANT_ID" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import platform
import shutil
import sys
import uuid

output = pathlib.Path(sys.argv[1])
tenant_id = sys.argv[2]
if not tenant_id.strip():
    raise SystemExit("BLOCK: tenant id must not be empty")
tools = (
    "terraform", "tofu", "kubectl", "oc", "docker", "podman", "qm",
    "pvesh", "virsh", "govc", "vboxmanage", "cloudmonkey", "aws", "az",
    "gcloud", "aliyun", "hcloud"
)
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
hostname_hash = hashlib.sha256(platform.node().encode()).hexdigest()
payload = {
    "observation_version": "local-inventory-v1",
    "collection_mode": "read-only",
    "collected_at": now,
    "host": {
        "os_family": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "kernel": platform.version(),
        "hostname_sha256": hostname_hash,
    },
    "tools": {name: shutil.which(name) is not None for name in tools},
    "safety": {
        "external_commands_invoked": False,
        "network_calls": 0,
        "credentials_used": False,
    },
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
envelope = {
    "envelope_id": str(uuid.uuid4()),
    "tenant_id": tenant_id,
    "schema_version": "evidence-envelope-v1",
    "event_type": "local.host.inventory.observed",
    "collected_at": now,
    "collector": "a2z-local-inventory/0.1",
    "integrity": {
        "algorithm": "sha256",
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
    },
    "payload": payload,
}
output.write_text(json.dumps(envelope, indent=2) + "\n")
print(f"ALLOW: wrote read-only inventory evidence to {output}")
print(f"payload_sha256={envelope['integrity']['payload_sha256']}")
PY
