#!/usr/bin/env bash
set -euo pipefail

ATTESTATION_FILE="${1:?usage: verify-runner-attestation.sh <attestation.json>}"
TRUST_DIR="${A2Z_RUNNER_TRUST_DIR:-}"
[[ -f "$ATTESTATION_FILE" && ! -L "$ATTESTATION_FILE" ]] || {
  echo "BLOCK: runner attestation must be a regular non-symlink file" >&2
  exit 42
}
[[ -n "$TRUST_DIR" && -d "$TRUST_DIR" && ! -L "$TRUST_DIR" ]] || {
  echo "BLOCK: A2Z_RUNNER_TRUST_DIR must be a real directory" >&2
  exit 40
}
[[ "$(stat -c %u -- "$TRUST_DIR")" == "0" ]] || {
  echo "BLOCK: runner attestation trust directory must be root-owned" >&2
  exit 43
}
TRUST_MODE="$(stat -c %a -- "$TRUST_DIR")"
(( (8#$TRUST_MODE & 0027) == 0 )) || {
  echo "BLOCK: runner attestation trust directory permissions are too broad" >&2
  exit 44
}
TRUST_PARENT="$(dirname -- "$TRUST_DIR")"
[[ -d "$TRUST_PARENT" && ! -L "$TRUST_PARENT" && "$(stat -c %u -- "$TRUST_PARENT")" == "0" ]] || {
  echo "BLOCK: runner attestation trust parent must be root-owned" >&2
  exit 45
}
PARENT_MODE="$(stat -c %a -- "$TRUST_PARENT")"
(( (8#$PARENT_MODE & 0022) == 0 )) || {
  echo "BLOCK: runner attestation trust parent is group/other writable" >&2
  exit 46
}
FILE_SIZE="$(stat -c %s -- "$ATTESTATION_FILE")"
(( FILE_SIZE <= 65536 )) || {
  echo "BLOCK: runner attestation exceeds 64 KiB" >&2
  exit 47
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
KEY_ID="$(python3 - "$ATTESTATION_FILE" <<'PY'
import json, pathlib, re, sys
def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SystemExit("BLOCK: duplicate JSON key")
        result[key] = value
    return result
record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), object_pairs_hook=pairs)
if not isinstance(record, dict) or set(record) != {"attestation", "signature"}:
    raise SystemExit("BLOCK: invalid runner attestation envelope")
sig = record["signature"]
if not isinstance(sig, dict) or set(sig) != {"algorithm", "key_id", "signature_base64"} or sig.get("algorithm") != "ed25519":
    raise SystemExit("BLOCK: invalid Ed25519 signature envelope")
key_id = sig.get("key_id", "")
if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id):
    raise SystemExit("BLOCK: invalid key id")
print(key_id)
PY
)"
KEY_PATH="${TRUST_DIR}/${KEY_ID}.pem"
[[ -f "$KEY_PATH" && ! -L "$KEY_PATH" && "$(stat -c %u -- "$KEY_PATH")" == "0" ]] || {
  echo "BLOCK: runner attestation public key is not root-owned in the trust directory" >&2
  exit 48
}
KEY_MODE="$(stat -c %a -- "$KEY_PATH")"
(( (8#$KEY_MODE & 0022) == 0 )) || {
  echo "BLOCK: runner attestation public key is group/other writable" >&2
  exit 49
}

python3 - "$ATTESTATION_FILE" "$TMP_DIR" <<'PY'
import base64, hashlib, json, pathlib, sys
def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SystemExit("BLOCK: duplicate JSON key")
        result[key] = value
    return result
record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), object_pairs_hook=pairs)
attestation = record["attestation"]
try:
    signature = base64.b64decode(record["signature"]["signature_base64"], validate=True)
except (KeyError, ValueError, TypeError) as exc:
    raise SystemExit(f"BLOCK: invalid signature encoding: {exc}")
payload = json.dumps({"domain": "a2z.runner-attestation.v1", "attestation": attestation}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
temp = pathlib.Path(sys.argv[2])
(temp / "payload.json").write_bytes(payload)
(temp / "signature.bin").write_bytes(signature)
print(f"runner_attestation_sha256={hashlib.sha256(payload).hexdigest()}")
PY

openssl pkeyutl -verify -pubin -inkey "$KEY_PATH" -rawin \
  -in "$TMP_DIR/payload.json" -sigfile "$TMP_DIR/signature.bin" >/dev/null
echo "ALLOW: runner attestation signature verified"
