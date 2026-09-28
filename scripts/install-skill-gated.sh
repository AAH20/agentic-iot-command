#!/usr/bin/env bash
set -euo pipefail

SOURCE="${1:?usage: install-skill-gated.sh <github-url-or-path> [skill-name] [approval.json]}"
SKILL_NAME="${2:-}"
APPROVAL_FILE="${3:-${A2Z_SKILL_APPROVAL_FILE:-}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUARANTINE="${ROOT}/.skill-quarantine"
REPORTS="${ROOT}/security-reports/skills"
mkdir -p "$QUARANTINE" "$REPORTS"

if [[ "$SOURCE" =~ ^https://github.com/([^/]+)/([^/]+)(/.*)?$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
  name="${SKILL_NAME:-${repo}}"
  ref="${A2Z_SKILL_REF:-}"
  if [[ ! "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "BLOCK: A2Z_SKILL_REF must be a 40-character immutable commit SHA" >&2
    exit 19
  fi
  target="${QUARANTINE}/${owner}-${repo}-${ref}"
  if [[ -e "$target" ]]; then
    echo "BLOCK: quarantine target already exists; preserve it as evidence" >&2
    exit 26
  fi
  repo_url="https://github.com/${owner}/${repo}.git"
  git clone --no-checkout --filter=blob:none --depth 1 "$repo_url" "$target"
  git -C "$target" fetch --depth 1 origin "$ref"
  git -C "$target" checkout --detach "$ref"
  resolved_commit="$(git -C "$target" rev-parse HEAD)"
  [[ "$resolved_commit" == "$ref" ]] || {
    echo "BLOCK: cloned revision does not match the requested commit" >&2
    exit 27
  }
else
  name="${SKILL_NAME:-$(basename "$SOURCE")}";
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || {
    echo "BLOCK: invalid skill name" >&2
    exit 28
  }
  target="${QUARANTINE}/${name}"
  if [[ -e "$target" ]]; then
    echo "BLOCK: quarantine target already exists; preserve it as evidence" >&2
    exit 26
  fi
  mkdir "$target"
  python3 - "$SOURCE" "$target" <<'PY'
import pathlib, shutil, sys
shutil.copytree(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), dirs_exist_ok=True, symlinks=True)
PY
  resolved_commit=""
fi

artifact_digest="$(python3 - "$target" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
symlinks = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_symlink())
if symlinks:
    raise SystemExit(f"BLOCK: artifact contains symlinks outside the regular-file scan contract: {symlinks[:20]}")
h = hashlib.sha256()
for path in sorted(p for p in root.rglob("*") if p.is_file()):
    rel = path.relative_to(root).as_posix().encode()
    h.update(len(rel).to_bytes(8, "big"))
    h.update(rel)
    data = path.read_bytes()
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)
print(h.hexdigest())
PY
)"

report="${REPORTS}/${name}.json"
set +e
"${ROOT}/scripts/scan-skill.sh" "$target" "$report"
scan_status=$?
set -e
if [[ "$scan_status" -ne 0 && "$scan_status" -ne 10 ]]; then
  exit "$scan_status"
fi
report_digest="$(shasum -a 256 "$report" | awk '{print $1}')"

if [[ -z "$APPROVAL_FILE" || ! -f "$APPROVAL_FILE" ]]; then
  echo "BLOCK: scan is eligible for owner review, but a signed approval record is required before installation" >&2
  echo "artifact_id=sha256:${artifact_digest}" >&2
  echo "report_sha256=${report_digest}" >&2
  if [[ "$scan_status" -eq 10 ]]; then
    echo "review_material:" >&2
    python3 "${ROOT}/scripts/skill_gate.py" review-material "$report" "$ROOT/policies/skill-gate.json" >&2
  fi
  exit 29
fi

if [[ -z "${A2Z_APPROVAL_VERIFY_BIN:-}" || ! -x "${A2Z_APPROVAL_VERIFY_BIN}" ]]; then
  echo "BLOCK: set A2Z_APPROVAL_VERIFY_BIN to the pinned approval-signature verifier" >&2
  exit 31
fi
"$A2Z_APPROVAL_VERIFY_BIN" "$APPROVAL_FILE"

python3 "${ROOT}/scripts/skill_gate.py" validate-approval \
  "$report" "$ROOT/policies/skill-gate.json" "$APPROVAL_FILE" \
  "$artifact_digest" "$report_digest"

if [[ -z "${A2Z_SKILLS_BIN:-}" || ! -x "${A2Z_SKILLS_BIN}" ]]; then
  echo "BLOCK: set A2Z_SKILLS_BIN to an installed, pinned skills CLI binary" >&2
  exit 30
fi

if [[ -n "$SKILL_NAME" ]]; then
  "$A2Z_SKILLS_BIN" add "$target" --skill "$SKILL_NAME"
else
  "$A2Z_SKILLS_BIN" add "$target"
fi
