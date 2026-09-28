#!/usr/bin/env bash
set -euo pipefail

APPROVAL_FILE="${1:?usage: verify-approval.sh <approval.json>}"
TRUST_DIR="${A2Z_APPROVAL_TRUST_DIR:-}"

[[ -f "$APPROVAL_FILE" ]] || {
  echo "BLOCK: approval record does not exist" >&2
  exit 42
}

if [[ -z "$TRUST_DIR" || ! -d "$TRUST_DIR" ]]; then
  echo "BLOCK: A2Z_APPROVAL_TRUST_DIR must point to the approval public-key directory" >&2
  exit 40
fi
file_owner() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f %u "$1"
  else
    stat -c %u "$1"
  fi
}
file_mode() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f %Lp "$1"
  else
    stat -c %a "$1"
  fi
}

[[ ! -L "$TRUST_DIR" && "$(file_owner "$TRUST_DIR")" == "0" ]] || {
  echo "BLOCK: approval trust directory must be a real root-owned directory" >&2
  exit 43
}
TRUST_MODE="$(file_mode "$TRUST_DIR")"
(( (8#$TRUST_MODE & 0027) == 0 )) || {
  echo "BLOCK: approval trust directory permissions are too broad" >&2
  exit 44
}
TRUST_PARENT="$(dirname "$TRUST_DIR")"
[[ ! -L "$TRUST_PARENT" && -d "$TRUST_PARENT" && "$(file_owner "$TRUST_PARENT")" == "0" ]] || {
  echo "BLOCK: approval trust directory parent must be a real root-owned directory" >&2
  exit 46
}
PARENT_MODE="$(file_mode "$TRUST_PARENT")"
(( (8#$PARENT_MODE & 0022) == 0 )) || {
  echo "BLOCK: approval trust directory parent must not be group/other writable" >&2
  exit 47
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

KEY_ID="$(python3 - "$APPROVAL_FILE" <<'PY'
import json, re, sys
record = json.load(open(sys.argv[1]))
signature = record.get("signature")
if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
    raise SystemExit("BLOCK: approval record must contain an Ed25519 signature")
key_id = signature.get("key_id", "")
if not re.fullmatch(r"[A-Za-z0-9._-]+", key_id):
    raise SystemExit("BLOCK: invalid approval key id")
print(key_id)
PY
)"
KEY_PATH="${TRUST_DIR}/${KEY_ID}.pem"
[[ -f "$KEY_PATH" && ! -L "$KEY_PATH" && "$(file_owner "$KEY_PATH")" == "0" ]] || {
  echo "BLOCK: approval key is not in the configured trust directory" >&2
  exit 41
}
KEY_MODE="$(file_mode "$KEY_PATH")"
(( (8#$KEY_MODE & 0022) == 0 )) || {
  echo "BLOCK: approval public key must not be group/other writable" >&2
  exit 45
}

python3 - "$APPROVAL_FILE" "$TMP_DIR" <<'PY'
import base64, hashlib, json, pathlib, sys
record = json.loads(pathlib.Path(sys.argv[1]).read_text())
approval = record.get("approval")
signature = record.get("signature")
if not isinstance(approval, dict) or not isinstance(signature, dict):
    raise SystemExit("BLOCK: approval record must contain approval and signature objects")
try:
    signature_bytes = base64.b64decode(signature["signature_base64"], validate=True)
except (KeyError, ValueError) as exc:
    raise SystemExit(f"BLOCK: invalid approval signature encoding: {exc}")
canonical = json.dumps(approval, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
tmp_dir = pathlib.Path(sys.argv[2])
(tmp_dir / "payload.json").write_bytes(canonical)
(tmp_dir / "signature.bin").write_bytes(signature_bytes)
print(f"approval_payload_sha256={hashlib.sha256(canonical).hexdigest()}")
PY

openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$KEY_PATH" \
  -rawin \
  -in "$TMP_DIR/payload.json" \
  -sigfile "$TMP_DIR/signature.bin" \
  >/dev/null

echo "ALLOW: approval signature verified"
