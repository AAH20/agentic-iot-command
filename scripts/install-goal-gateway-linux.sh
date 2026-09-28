#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "BLOCK: run this installer as root after reviewing the package and target account" >&2
  exit 77
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACCOUNT="a2z-control"
ACCOUNT_INFO="$(getent passwd "$ACCOUNT" || true)"
[[ -n "$ACCOUNT_INFO" ]] || {
  echo "BLOCK: create and review the dedicated a2z-control account before installation" >&2
  exit 78
}
ACCOUNT_SHELL="$(cut -d: -f7 <<<"$ACCOUNT_INFO")"
if [[ "$ACCOUNT_SHELL" != "/bin/bash" && "$ACCOUNT_SHELL" != "/bin/sh" ]]; then
  echo "BLOCK: a2z-control needs a reviewed usable shell for its forced stdio gateway" >&2
  exit 82
fi

ACCOUNT_GROUPS="$(id -nG "$ACCOUNT")"
ACCOUNT_GROUP="$(id -gn "$ACCOUNT")"
for forbidden in sudo wheel vboxusers libvirt docker lxd disk; do
  if [[ " ${ACCOUNT_GROUPS} " == *" ${forbidden} "* ]]; then
    echo "BLOCK: a2z-control is in the forbidden ${forbidden} group" >&2
    exit 79
  fi
done

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("BLOCK: Python 3.11 or later is required")
PY
[[ -x /usr/bin/openssl && ! -L /usr/bin/openssl ]] || {
  echo "BLOCK: fixed /usr/bin/openssl is required for Ed25519 grant verification" >&2
  exit 80
}
/usr/bin/openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519 || {
  echo "BLOCK: /usr/bin/openssl must support Ed25519" >&2
  exit 80
}

for path in \
  /opt/a2z-control-plane \
  /etc/a2z-control-plane \
  /etc/a2z-control-plane/goal-gateway.json \
  /etc/a2z-control-plane/execution-control.json \
  /etc/a2z-control-plane/runner-trust \
  /etc/a2z-control-plane/execution-grant-trust \
  /etc/a2z-control-plane/impact-assessment-trust \
  /var/lib/a2z-control-plane \
  /usr/local/libexec/a2z-goal-gateway; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "BLOCK: destination already exists; review it instead of overwriting: $path" >&2
    exit 81
  fi
done

install -d -o root -g root -m 0755 \
  /opt/a2z-control-plane/src/control_plane_core \
  /opt/a2z-control-plane/scripts \
  /etc/a2z-control-plane
install -d -o root -g "$ACCOUNT_GROUP" -m 0750 \
  /etc/a2z-control-plane/approval-trust \
  /etc/a2z-control-plane/runner-trust \
  /etc/a2z-control-plane/execution-grant-trust \
  /etc/a2z-control-plane/impact-assessment-trust
for module in __init__.py approval.py autonomy.py autonomy_catalog.py autonomy_profiles.py goals.py runner_attestations.py execution_grants.py execution_controls.py impact_assessments.py; do
  install -o root -g root -m 0644 \
    "$ROOT/src/control_plane_core/$module" \
    "/opt/a2z-control-plane/src/control_plane_core/$module"
done
install -o root -g root -m 0644 \
  "$ROOT/scripts/mcp_goal_journal.py" \
  /opt/a2z-control-plane/scripts/mcp_goal_journal.py
install -o root -g root -m 0755 \
  "$ROOT/scripts/verify-autonomy-profile.sh" \
  /opt/a2z-control-plane/scripts/verify-autonomy-profile.sh
install -o root -g root -m 0755 \
  "$ROOT/scripts/verify-approval.sh" \
  /opt/a2z-control-plane/scripts/verify-approval.sh
install -o root -g root -m 0755 \
  "$ROOT/scripts/verify-runner-attestation.sh" \
  /opt/a2z-control-plane/scripts/verify-runner-attestation.sh
install -o root -g root -m 0755 \
  "$ROOT/scripts/verify-execution-grant.sh" \
  /opt/a2z-control-plane/scripts/verify-execution-grant.sh
install -o root -g root -m 0755 \
  "$ROOT/scripts/verify-impact-assessment.sh" \
  /opt/a2z-control-plane/scripts/verify-impact-assessment.sh
install -o root -g root -m 0755 \
  "$ROOT/scripts/a2z-goal-gateway" \
  /usr/local/libexec/a2z-goal-gateway
install -o root -g "$ACCOUNT_GROUP" -m 0640 \
  "$ROOT/config/goal-gateway-server.example.json" \
  /etc/a2z-control-plane/goal-gateway.json
install -o root -g "$ACCOUNT_GROUP" -m 0640 \
  "$ROOT/config/execution-control.disabled.json" \
  /etc/a2z-control-plane/execution-control.json
install -d -o "$ACCOUNT" -g "$ACCOUNT_GROUP" -m 0700 /var/lib/a2z-control-plane

echo "ALLOW: non-executing Ubuntu goal gateway installed"
echo "INFO: no SSH key, sshd rule, firewall, VirtualBox access, worker, or mutation executor was configured"
echo "INFO: add reviewed Ed25519 approval public keys root-owned under /etc/a2z-control-plane/approval-trust"
echo "INFO: runner receipt verification is evidence-only; no runner or mutation path is installed"
echo "INFO: execution-grant verification is a contract only; no grant issuer, signing key, or worker is installed"
echo "INFO: global execution kill switch is installed disabled; only root may enable it with a fresh, at-most-1-hour window"
echo "INFO: add reviewed Ed25519 runner public keys root-owned under /etc/a2z-control-plane/runner-trust only when a separately reviewed runner exists"
echo "INFO: review /etc/a2z-control-plane/goal-gateway.json as root before accepting the restricted SSH key"
