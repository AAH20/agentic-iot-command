#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "BLOCK: run this staged installer as root after reviewing the package" >&2
  exit 77
fi

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
ACCOUNT="a2z-control"
SIGNER_ACCOUNT="a2z-grant-signer"
ACCOUNT_INFO="$(getent passwd "$ACCOUNT" || true)"
[[ -n "$ACCOUNT_INFO" ]] || {
  echo "BLOCK: install and review the non-executing goal gateway first" >&2
  exit 78
}
ACCOUNT_GROUP="$(id -gn "$ACCOUNT")"
ACCOUNT_GROUPS="$(id -nG "$ACCOUNT")"
if [[ "$ACCOUNT_GROUP" != "$ACCOUNT" ]]; then
  echo "BLOCK: a2z-control must use its dedicated primary group" >&2
  exit 78
fi
for forbidden in sudo wheel vboxusers libvirt docker lxd disk; do
  if [[ " $ACCOUNT_GROUPS " == *" $forbidden "* ]]; then
    echo "BLOCK: a2z-control is in the forbidden $forbidden group" >&2
    exit 79
  fi
done
if [[ -z "$(getent passwd "$SIGNER_ACCOUNT" || true)" \
      || -z "$(getent group "$SIGNER_ACCOUNT" || true)" \
      || "$(id -gn "$SIGNER_ACCOUNT")" != "$SIGNER_ACCOUNT" \
      || "$(id -nG "$SIGNER_ACCOUNT")" != "$SIGNER_ACCOUNT" ]]; then
  echo "BLOCK: install and review the separate a2z-grant-signer identity first" >&2
  exit 78
fi

if [[ ! -r /etc/os-release ]]; then
  echo "BLOCK: cannot verify Ubuntu release" >&2
  exit 80
fi
. /etc/os-release
if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "26.04" ]]; then
  echo "BLOCK: this staged installer targets Ubuntu 26.04 only" >&2
  exit 80
fi
/usr/bin/python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("BLOCK: Python 3.11 or later is required")
PY
[[ -x /usr/bin/openssl && ! -L /usr/bin/openssl \
   && -d /etc/systemd/system && ! -L /etc/systemd/system ]] || {
  echo "BLOCK: fixed OpenSSL and systemd are required" >&2
  exit 80
}
/usr/bin/openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519 || {
  echo "BLOCK: /usr/bin/openssl must support Ed25519" >&2
  exit 80
}
/usr/bin/python3 - <<'PY'
import os
import stat
path = "/usr/bin/openssl"
info = os.stat(path, follow_symlinks=False)
if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
    raise SystemExit("BLOCK: /usr/bin/openssl must be root-owned and not group/other writable")
PY

for path in \
  /etc/a2z-control-plane \
  /etc/a2z-control-plane/approval-trust \
  /etc/a2z-control-plane/runner-trust \
  /etc/a2z-control-plane/execution-grant-trust \
  /etc/a2z-control-plane/impact-assessment-trust \
  /etc/a2z-control-plane/execution-control.json \
  /var/lib/a2z-control-plane \
  /etc/systemd/system/a2z-grant-signer.socket; do
  if [[ ! -e "$path" || -L "$path" ]]; then
    echo "BLOCK: install the base gateway and grant signer first; missing or unsafe: $path" >&2
    exit 80
  fi
done
if [[ "$(stat -c '%U:%a' /var/lib/a2z-control-plane)" != "$ACCOUNT:700" \
      || "$(stat -c '%U' /etc/a2z-control-plane)" != "root" ]]; then
  echo "BLOCK: journal directory must be a2z-control-owned 0700 and config root-owned" >&2
  exit 80
fi
for trust_dir in approval-trust runner-trust execution-grant-trust impact-assessment-trust; do
  if [[ "$(stat -c '%U' "/etc/a2z-control-plane/$trust_dir")" != "root" ]]; then
    echo "BLOCK: trust directory must be root-owned: $trust_dir" >&2
    exit 80
  fi
done
/usr/bin/python3 - <<'PY'
import json
import os
import stat
def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
path = "/etc/a2z-control-plane/execution-control.json"
info = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o027:
    raise SystemExit("BLOCK: execution kill switch must be root-owned and protected")
with open(path, encoding="utf-8") as stream:
    record = json.load(stream, object_pairs_hook=_unique)
if record.get("schema_version") != "a2z-execution-control-v1" or record.get("execution_enabled") is not False:
    raise SystemExit("BLOCK: execution kill switch must remain disabled during worker API installation")
PY

for path in \
  /opt/a2z-worker-api \
  /etc/a2z-control-plane/worker-api.json \
  /etc/a2z-control-plane/runner-identities.json \
  /etc/a2z-control-plane/worker-tls \
  /etc/a2z-control-plane/autonomy-profile-trust \
  /etc/systemd/system/a2z-worker-api.service; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "BLOCK: destination already exists; review it instead of overwriting: $path" >&2
    exit 81
  fi
done

for source in \
  src/control_plane_core/__init__.py \
  src/control_plane_core/worker_api.py \
  src/control_plane_core/worker_api_registry.py \
  src/control_plane_core/worker_api_service.py \
  scripts/worker-api-server.py \
  scripts/verify-approval.sh \
  scripts/verify-autonomy-profile.sh \
  scripts/verify-impact-assessment.sh \
  scripts/verify-execution-grant.sh \
  scripts/verify-runner-attestation.sh \
  config/worker-api.example.json \
  config/worker-identities.example.json \
  schemas/worker-api-config.schema.json \
  schemas/runner-certificate-registry.schema.json \
  deploy/systemd/a2z-worker-api.service; do
  if [[ ! -f "$ROOT/$source" || -L "$ROOT/$source" ]]; then
    echo "BLOCK: reviewed source file is missing or a symlink: $source" >&2
    exit 82
  fi
done
if find "$ROOT/src/control_plane_core" -type l -print -quit | grep -q .; then
  echo "BLOCK: control-plane package contains a symlink; review package contents" >&2
  exit 82
fi

install -d -o root -g root -m 0755 \
  /opt/a2z-worker-api/src/control_plane_core \
  /opt/a2z-worker-api/scripts \
  /opt/a2z-worker-api/config \
  /opt/a2z-worker-api/schemas
while IFS= read -r -d '' source; do
  relative="${source#"$ROOT/src/control_plane_core/"}"
  destination="/opt/a2z-worker-api/src/control_plane_core/$relative"
  install -d -o root -g root -m 0755 "$(dirname "$destination")"
  install -o root -g root -m 0644 "$source" "$destination"
done < <(find "$ROOT/src/control_plane_core" -type f -name '*.py' ! -path '*/__pycache__/*' -print0)
for verifier in verify-approval.sh verify-autonomy-profile.sh verify-impact-assessment.sh \
  verify-execution-grant.sh verify-runner-attestation.sh; do
  install -o root -g root -m 0755 "$ROOT/scripts/$verifier" "/opt/a2z-worker-api/scripts/$verifier"
done
install -o root -g root -m 0755 \
  "$ROOT/scripts/worker-api-server.py" /opt/a2z-worker-api/scripts/worker-api-server.py
install -o root -g root -m 0644 \
  "$ROOT/config/worker-api.example.json" \
  "$ROOT/config/worker-identities.example.json" \
  /opt/a2z-worker-api/config/
install -o root -g root -m 0644 \
  "$ROOT/schemas/worker-api-config.schema.json" \
  "$ROOT/schemas/runner-certificate-registry.schema.json" \
  /opt/a2z-worker-api/schemas/
install -o root -g root -m 0644 \
  "$ROOT/deploy/systemd/a2z-worker-api.service" \
  /etc/systemd/system/a2z-worker-api.service
install -d -o root -g "$ACCOUNT_GROUP" -m 0750 \
  /etc/a2z-control-plane/worker-tls \
  /etc/a2z-control-plane/autonomy-profile-trust

echo "ALLOW: worker API code and stopped systemd unit installed; listener remains disabled"
echo "INFO: no active worker config, runner registry, TLS key/certificate, or trust keys were created"
echo "INFO: no daemon-reload, service start/enable, network/firewall, SSH, VM, cloud, or execution-switch changes"
echo "INFO: configure one reviewed runner certificate, exact lab UUID/action scope, trust keys, and loopback TLS before validation"
