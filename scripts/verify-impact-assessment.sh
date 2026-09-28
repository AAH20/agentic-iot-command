#!/usr/bin/env bash
set -euo pipefail

ASSESSMENT_FILE="${1:?usage: verify-impact-assessment.sh <assessment-envelope.json>}"
TRUST_DIR="${A2Z_IMPACT_TRUST_DIR:-}"
[[ -f "$ASSESSMENT_FILE" && ! -L "$ASSESSMENT_FILE" ]] || {
  echo "BLOCK: impact assessment must be a regular non-symlink file" >&2
  exit 42
}
[[ -n "$TRUST_DIR" && -d "$TRUST_DIR" && ! -L "$TRUST_DIR" ]] || {
  echo "BLOCK: A2Z_IMPACT_TRUST_DIR must name a real trusted-key directory" >&2
  exit 40
}
/usr/bin/python3 - "$TRUST_DIR" <<'PY'
import os, pathlib, stat, sys
p = pathlib.Path(sys.argv[1])
s = p.stat()
if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode) & 0o027:
    raise SystemExit("BLOCK: impact trust directory permissions are too broad")
if os.name == "posix" and s.st_uid != 0:
    raise SystemExit("BLOCK: impact trust directory must be root-owned")
PY

TMP_DIR="$(/usr/bin/mktemp -d)"
trap '/bin/rm -rf -- "$TMP_DIR"' EXIT

/usr/bin/python3 - "$ASSESSMENT_FILE" "$TRUST_DIR" "$TMP_DIR" <<'PY'
import base64, json, os, pathlib, re, stat, sys

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

file_path, trust_path, temp_path = map(pathlib.Path, sys.argv[1:])
if file_path.stat().st_size > 65536:
    raise SystemExit("BLOCK: impact assessment too large")
record = json.loads(file_path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
if not isinstance(record, dict) or set(record) != {"assessment", "signature"}:
    raise SystemExit("BLOCK: invalid assessment envelope")
assessment, signature = record["assessment"], record["signature"]
if not isinstance(assessment, dict) or not isinstance(signature, dict):
    raise SystemExit("BLOCK: invalid assessment or signature object")
key_id = signature.get("key_id", "")
if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id):
    raise SystemExit("BLOCK: invalid impact signing key ID")
if signature.get("algorithm") != "ed25519":
    raise SystemExit("BLOCK: impact signature algorithm must be Ed25519")
try:
    signature_bytes = base64.b64decode(signature["signature_base64"], validate=True)
except (KeyError, ValueError, TypeError) as exc:
    raise SystemExit("BLOCK: invalid impact signature encoding") from exc
key_path = trust_path / (key_id + ".pem")
if key_path.is_symlink() or not key_path.is_file():
    raise SystemExit("BLOCK: impact signing key is not trusted")
key_stat = key_path.stat()
if not stat.S_ISREG(key_stat.st_mode) or stat.S_IMODE(key_stat.st_mode) & 0o022:
    raise SystemExit("BLOCK: impact public key permissions are too broad")
canonical = json.dumps({"domain": "a2z.impact-assessment.v1", "assessment": assessment},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
if len(canonical) > 32768:
    raise SystemExit("BLOCK: canonical impact assessment exceeds 32 KiB")
(temp_path / "payload.json").write_bytes(canonical)
(temp_path / "signature.bin").write_bytes(signature_bytes)
os.chmod(temp_path / "payload.json", 0o600)
os.chmod(temp_path / "signature.bin", 0o600)
PY

/usr/bin/openssl pkeyutl -verify -pubin \
  -inkey "$TRUST_DIR/$(/usr/bin/python3 - "$ASSESSMENT_FILE" <<'PY'
import json, pathlib, re, sys
record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
key_id = record["signature"]["key_id"]
if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id):
    raise SystemExit("invalid key ID")
print(key_id)
PY
).pem" \
  -rawin -in "$TMP_DIR/payload.json" -sigfile "$TMP_DIR/signature.bin" >/dev/null

echo "ALLOW: impact assessment signature verified"
