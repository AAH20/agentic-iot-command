#!/usr/bin/env bash
set -euo pipefail

PROFILE_FILE="${1:?usage: verify-autonomy-profile.sh <signed-profile.json>}"
TRUST_DIR="${A2Z_AUTONOMY_TRUST_DIR:-}"

[[ -f "$PROFILE_FILE" && ! -L "$PROFILE_FILE" ]] || {
  echo "BLOCK: signed autonomy profile is not a regular file" >&2
  exit 42
}
[[ -n "$TRUST_DIR" && -d "$TRUST_DIR" ]] || {
  echo "BLOCK: A2Z_AUTONOMY_TRUST_DIR must name the policy public-key trust directory" >&2
  exit 40
}
[[ ! -L "$TRUST_DIR" ]] || {
  echo "BLOCK: autonomy trust directory may not be a symlink" >&2
  exit 40
}
python3 - "$TRUST_DIR" <<'PY'
import pathlib, stat, sys
p = pathlib.Path(sys.argv[1])
s = p.stat()
if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode) & 0o027:
    raise SystemExit("BLOCK: autonomy trust directory must not be group-writable or accessible by other users")
PY

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

KEY_ID="$(python3 - "$PROFILE_FILE" <<'PY'
import json, pathlib, re, sys
p = pathlib.Path(sys.argv[1])
if p.stat().st_size > 1024 * 1024:
    raise SystemExit("BLOCK: profile too large")
record = json.loads(p.read_text(encoding="utf-8"))
if not isinstance(record, dict) or set(record) != {"profile", "signature"}:
    raise SystemExit("BLOCK: envelope must contain profile and signature")
sig = record["signature"]
if not isinstance(sig, dict) or set(sig) != {"algorithm", "key_id", "signature_base64"} or sig.get("algorithm") != "ed25519":
    raise SystemExit("BLOCK: invalid Ed25519 signature envelope")
key_id = sig.get("key_id", "")
if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", key_id):
    raise SystemExit("BLOCK: invalid key id")
print(key_id)
PY
)"
KEY_PATH="${TRUST_DIR}/${KEY_ID}.pem"
[[ -f "$KEY_PATH" && ! -L "$KEY_PATH" ]] || {
  echo "BLOCK: autonomy signing key is not in the configured trust directory" >&2
  exit 41
}
python3 - "$KEY_PATH" <<'PY'
import pathlib, stat, sys
p = pathlib.Path(sys.argv[1])
s = p.stat()
if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) & 0o022:
    raise SystemExit("BLOCK: autonomy public key must be a regular file, not group/other writable")
PY

python3 - "$PROFILE_FILE" "$TMP_DIR" <<'PY'
import base64, hashlib, json, pathlib, sys
record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
profile = record["profile"]
signature = record["signature"]
try:
    signature_bytes = base64.b64decode(signature["signature_base64"], validate=True)
except (KeyError, ValueError, TypeError) as exc:
    raise SystemExit(f"BLOCK: invalid signature encoding: {exc}")
signed = {"domain": "a2z.autonomy-profile.v1", "profile": profile}
canonical = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
tmp = pathlib.Path(sys.argv[2])
(tmp / "payload.json").write_bytes(canonical)
(tmp / "signature.bin").write_bytes(signature_bytes)
print(f"autonomy_policy_sha256={hashlib.sha256(canonical).hexdigest()}")
PY

openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$KEY_PATH" \
  -rawin \
  -in "$TMP_DIR/payload.json" \
  -sigfile "$TMP_DIR/signature.bin" \
  >/dev/null

echo "ALLOW: autonomy profile signature verified"
