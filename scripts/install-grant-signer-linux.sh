#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "BLOCK: run this staged installer as root after reviewing the package" >&2
  exit 77
fi

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
API_ACCOUNT="a2z-control"
SIGNER_ACCOUNT="a2z-grant-signer"
SIGNER_GROUP="a2z-grant-signer"
API_INFO="$(getent passwd "$API_ACCOUNT" || true)"
[[ -n "$API_INFO" ]] || {
  echo "BLOCK: install and review the non-executing a2z-control goal gateway first" >&2
  exit 78
}
API_GROUP="$(id -gn "$API_ACCOUNT")"
API_GROUPS="$(id -nG "$API_ACCOUNT")"
if [[ "$API_GROUP" != "$API_ACCOUNT" ]]; then
  echo "BLOCK: a2z-control must use its dedicated primary group" >&2
  exit 78
fi
for forbidden in sudo wheel vboxusers libvirt docker lxd disk; do
  if [[ " $API_GROUPS " == *" $forbidden "* ]]; then
    echo "BLOCK: a2z-control is in the forbidden $forbidden group" >&2
    exit 79
  fi
done
[[ -x /usr/sbin/nologin ]] || {
  echo "BLOCK: /usr/sbin/nologin is required for the isolated signer identity" >&2
  exit 80
}

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
[[ -x /usr/bin/openssl && ! -L /usr/bin/openssl ]] || {
  echo "BLOCK: fixed /usr/bin/openssl is required" >&2
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
[[ -d /etc/systemd/system && ! -L /etc/systemd/system ]] || {
  echo "BLOCK: systemd is required" >&2
  exit 80
}

if getent passwd "$SIGNER_ACCOUNT" >/dev/null || getent group "$SIGNER_GROUP" >/dev/null; then
  echo "BLOCK: signer account/group already exists; review it instead of modifying it" >&2
  exit 81
fi
for path in \
  /opt/a2z-grant-signer \
  /etc/a2z-grant-signer \
  /etc/systemd/system/a2z-grant-signer.service \
  /etc/systemd/system/a2z-grant-signer.socket \
  /run/a2z-grant-signer; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "BLOCK: destination already exists; review it instead of overwriting: $path" >&2
    exit 81
  fi
done

for source in \
  src/control_plane_core/__init__.py \
  src/control_plane_core/execution_grants.py \
  src/control_plane_core/grant_signer_service.py \
  scripts/grant-signer-server.py \
  config/grant-signer.example.json \
  schemas/grant-signer-config.schema.json \
  deploy/systemd/a2z-grant-signer.service \
  deploy/systemd/a2z-grant-signer.socket; do
  if [[ ! -f "$ROOT/$source" || -L "$ROOT/$source" ]]; then
    echo "BLOCK: reviewed source file is missing or a symlink: $source" >&2
    exit 82
  fi
done
if find "$ROOT/src/control_plane_core" -type l -print -quit | grep -q .; then
  echo "BLOCK: control-plane package contains a symlink; review package contents" >&2
  exit 82
fi

# Create an independent service identity. It is not added to a2z-control,
# vboxusers, sudo, or any VM-management group.
groupadd --system "$SIGNER_GROUP"
useradd --system --gid "$SIGNER_GROUP" --home-dir /nonexistent \
  --shell /usr/sbin/nologin "$SIGNER_ACCOUNT"
if [[ "$(id -gn "$SIGNER_ACCOUNT")" != "$SIGNER_GROUP" \
      || "$(id -nG "$SIGNER_ACCOUNT")" != "$SIGNER_GROUP" \
      || "$(getent passwd "$SIGNER_ACCOUNT" | cut -d: -f7)" != "/usr/sbin/nologin" ]]; then
  echo "BLOCK: created signer identity does not match the required isolated account contract" >&2
  exit 83
fi

install -d -o root -g root -m 0755 \
  /opt/a2z-grant-signer/src/control_plane_core \
  /opt/a2z-grant-signer/scripts \
  /opt/a2z-grant-signer/config \
  /opt/a2z-grant-signer/schemas
while IFS= read -r -d '' source; do
  relative="${source#"$ROOT/src/control_plane_core/"}"
  destination="/opt/a2z-grant-signer/src/control_plane_core/$relative"
  install -d -o root -g root -m 0755 "$(dirname "$destination")"
  install -o root -g root -m 0644 "$source" "$destination"
done < <(find "$ROOT/src/control_plane_core" -type f -name '*.py' ! -path '*/__pycache__/*' -print0)
install -o root -g root -m 0755 \
  "$ROOT/scripts/grant-signer-server.py" \
  /opt/a2z-grant-signer/scripts/grant-signer-server.py
install -o root -g root -m 0644 \
  "$ROOT/config/grant-signer.example.json" \
  /opt/a2z-grant-signer/config/grant-signer.example.json
install -o root -g root -m 0644 \
  "$ROOT/schemas/grant-signer-config.schema.json" \
  /opt/a2z-grant-signer/schemas/grant-signer-config.schema.json
install -o root -g root -m 0644 \
  "$ROOT/deploy/systemd/a2z-grant-signer.service" \
  /etc/systemd/system/a2z-grant-signer.service
install -o root -g root -m 0644 \
  "$ROOT/deploy/systemd/a2z-grant-signer.socket" \
  /etc/systemd/system/a2z-grant-signer.socket
install -d -o root -g "$SIGNER_GROUP" -m 0750 /etc/a2z-grant-signer
install -d -o root -g "$SIGNER_GROUP" -m 0710 /etc/a2z-grant-signer/keys

echo "ALLOW: signer code, disabled units, and empty protected config/key directories installed"
echo "INFO: no config or key was created; no service was started/enabled and systemd was not reloaded"
echo "INFO: manually review config, provision the one selected VM UUID and API UID, then provision the signing key"
echo "INFO: API and signer identities remain separate; no SSH, firewall, VirtualBox, cloud, or execution-switch changes were made"
