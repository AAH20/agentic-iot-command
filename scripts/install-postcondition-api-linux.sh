#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "BLOCK: run this installer as root after reviewing the package and service account" >&2
  exit 77
fi

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
ACCOUNT="a2z-control"
ACCOUNT_INFO="$(getent passwd "$ACCOUNT" || true)"
[[ -n "$ACCOUNT_INFO" ]] || {
  echo "BLOCK: install the reviewed non-executing goal gateway and a2z-control account first" >&2
  exit 78
}
ACCOUNT_GROUP="$(id -gn "$ACCOUNT")"
ACCOUNT_GROUPS="$(id -nG "$ACCOUNT")"
if [[ "$ACCOUNT_GROUP" != "$ACCOUNT" ]]; then
  echo "BLOCK: a2z-control must use its dedicated a2z-control primary group" >&2
  exit 78
fi
for forbidden in sudo wheel vboxusers libvirt docker lxd disk; do
  if [[ " $ACCOUNT_GROUPS " == *" $forbidden "* ]]; then
    echo "BLOCK: a2z-control is in the forbidden $forbidden group" >&2
    exit 79
  fi
done

if [[ ! -r /etc/os-release ]]; then
  echo "BLOCK: cannot verify Ubuntu release" >&2
  exit 80
fi
. /etc/os-release
if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "26.04" ]]; then
  echo "BLOCK: this reviewed installer targets Ubuntu 26.04 only" >&2
  exit 80
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("BLOCK: Python 3.11 or later is required")
PY
[[ -x /usr/bin/openssl && ! -L /usr/bin/openssl ]] || {
  echo "BLOCK: fixed /usr/bin/openssl is required" >&2
  exit 80
}
/usr/bin/openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519 || {
  echo "BLOCK: /usr/bin/openssl must support Ed25519" >&2
  exit 80
}
[[ -d /etc/systemd/system && ! -L /etc/systemd/system
   && -d /etc/a2z-control-plane && ! -L /etc/a2z-control-plane
   && -d /var/lib/a2z-control-plane && ! -L /var/lib/a2z-control-plane ]] || {
  echo "BLOCK: install the base goal gateway and systemd before this separate service" >&2
  exit 80
}
if [[ "$(stat -c '%U:%a' /var/lib/a2z-control-plane)" != "$ACCOUNT:700" ]]; then
  echo "BLOCK: goal database directory must be owned by a2z-control with mode 0700" >&2
  exit 80
fi
if [[ "$(stat -c '%U' /etc/a2z-control-plane)" != "root" ]]; then
  echo "BLOCK: /etc/a2z-control-plane must be root-owned" >&2
  exit 80
fi
python3 - <<'PY'
import os
import stat
for path in ("/etc/a2z-control-plane", "/var/lib/a2z-control-plane"):
    info = os.stat(path, follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit(f"BLOCK: unsafe group/other write permission on {path}")
PY

INSTALL_ROOT="/opt/a2z-postcondition-api"
TRUST_DIR="/etc/a2z-control-plane/postcondition-attestation-trust"
TLS_DIR="/etc/a2z-control-plane/postcondition-tls"
SERVICE_FILE="/etc/systemd/system/a2z-postcondition-api.service"
for path in "$INSTALL_ROOT" "$TRUST_DIR" "$TLS_DIR" "$SERVICE_FILE"; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "BLOCK: destination already exists; review it instead of overwriting: $path" >&2
    exit 81
  fi
done
for path in \
  /etc/a2z-control-plane/postcondition-api.json \
  /etc/a2z-control-plane/postcondition-verifiers.json \
  /etc/a2z-control-plane/postcondition-tls/server.key; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "BLOCK: configuration/key destination already exists; review it manually: $path" >&2
    exit 81
  fi
done
for source in \
  src/control_plane_core/__init__.py \
  src/control_plane_core/autonomy.py \
  src/control_plane_core/autonomy_catalog.py \
  src/control_plane_core/autonomy_profiles.py \
  src/control_plane_core/impact_assessments.py \
  src/control_plane_core/goals.py \
  src/control_plane_core/worker_api.py \
  src/control_plane_core/postcondition_api.py \
  src/control_plane_core/postcondition_attestations.py \
  src/control_plane_core/postcondition_registry.py \
  src/control_plane_core/postcondition_server.py \
  scripts/postcondition-api-server.py \
  deploy/systemd/a2z-postcondition-api.service \
  config/postcondition-api.example.json \
  config/postcondition-verifiers.example.json \
  schemas/postcondition-api-config.schema.json \
  schemas/postcondition-verifier-registry.schema.json; do
  if [[ ! -f "$ROOT/$source" || -L "$ROOT/$source" ]]; then
    echo "BLOCK: reviewed source file is missing or a symlink: $source" >&2
    exit 82
  fi
done

install -d -o root -g root -m 0755 \
  "$INSTALL_ROOT/src/control_plane_core" \
  "$INSTALL_ROOT/scripts" \
  "$INSTALL_ROOT/config" \
  "$INSTALL_ROOT/schemas"
install -d -o root -g "$ACCOUNT_GROUP" -m 0750 "$TRUST_DIR" "$TLS_DIR"

for module in \
  __init__.py autonomy.py autonomy_catalog.py autonomy_profiles.py \
  impact_assessments.py goals.py worker_api.py postcondition_api.py \
  postcondition_attestations.py postcondition_registry.py postcondition_server.py; do
  install -o root -g root -m 0644 \
    "$ROOT/src/control_plane_core/$module" \
    "$INSTALL_ROOT/src/control_plane_core/$module"
done
install -o root -g root -m 0755 \
  "$ROOT/scripts/postcondition-api-server.py" \
  "$INSTALL_ROOT/scripts/postcondition-api-server.py"
install -o root -g root -m 0644 \
  "$ROOT/config/postcondition-api.example.json" \
  "$INSTALL_ROOT/config/postcondition-api.example.json"
install -o root -g root -m 0644 \
  "$ROOT/config/postcondition-verifiers.example.json" \
  "$INSTALL_ROOT/config/postcondition-verifiers.example.json"
install -o root -g root -m 0644 \
  "$ROOT/schemas/postcondition-api-config.schema.json" \
  "$ROOT/schemas/postcondition-verifier-registry.schema.json" \
  "$INSTALL_ROOT/schemas/"
install -o root -g root -m 0644 \
  "$ROOT/deploy/systemd/a2z-postcondition-api.service" "$SERVICE_FILE"

echo "ALLOW: verifier-only postcondition API files installed; service remains stopped and disabled"
echo "INFO: write reviewed root-owned config and verifier registry; install CA/server certs and public verifier key"
echo "INFO: TLS private key must be a2z-control-owned mode 0600; no key material was generated or copied"
echo "INFO: edit no existing gateway, SSH, firewall, VM, cloud, or mutation settings"
echo "INFO: run systemctl daemon-reload only after reviewing config, then test with the service stopped before enablement"
