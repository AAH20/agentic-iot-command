#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?usage: scan-skill.sh <path-or-url> <report.json> }"
REPORT="${2:?usage: scan-skill.sh <path-or-url> <report.json> }"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v skillspector >/dev/null 2>&1 || {
  echo "BLOCK: SkillSpector is not installed" >&2
  exit 20
}

if [[ "${SKILLSPECTOR_PROVIDER:-}" == "codex_cli" ]]; then
  command -v codex >/dev/null 2>&1 || {
    echo "BLOCK: SKILLSPECTOR_PROVIDER=codex_cli but Codex CLI is not on PATH" >&2
    exit 20
  }
  codex login status >/dev/null 2>&1 || {
    echo "BLOCK: Codex CLI is not authenticated; run codex login before semantic scanning" >&2
    exit 20
  }
elif [[ -z "${SKILLSPECTOR_PROVIDER:-}" ]]; then
  echo "INFO: set SKILLSPECTOR_PROVIDER explicitly for semantic scans (for example, codex_cli)." >&2
fi

mkdir -p "$(dirname "$REPORT")"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$TARGET" "$TMP" "$ROOT/policies/skill-gate.json" "${A2Z_SKILL_SCAN_SECONDS:-}" <<'PY'
import json, pathlib, re, subprocess, sys
target, report, policy_path, override = sys.argv[1:]
policy = json.loads(pathlib.Path(policy_path).read_text())
minimum = tuple(int(part) for part in policy["scanner"]["min_version"].split(".")[:3])
version_text = subprocess.run(["skillspector", "--version"], check=False, capture_output=True, text=True).stdout
match = re.search(r"(\d+\.\d+\.\d+)", version_text)
if not match or tuple(int(part) for part in match.group(1).split(".")) < minimum:
    raise SystemExit(f"BLOCK: SkillSpector version is below {policy['scanner']['min_version']}")
seconds = float(override) if override else float(policy["scanner"]["max_scan_seconds"])
command = ["skillspector", "scan", target, "--format", "json", "--output", report]
try:
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=seconds)
except subprocess.TimeoutExpired:
    raise SystemExit("BLOCK: SkillSpector scan timed out")
if result.stdout:
    print(result.stdout, end="")
if result.stderr:
    print(result.stderr, end="", file=sys.stderr)
if result.returncode:
    raise SystemExit(result.returncode)
PY

test -s "$TMP" || {
  echo "BLOCK: SkillSpector produced no report" >&2
  exit 21
}

python3 - "$TMP" "$REPORT" <<'PY'
import pathlib, shutil, sys
shutil.copyfile(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
PY
set +e
python3 "$ROOT/scripts/skill_gate.py" evaluate "$REPORT" "$ROOT/policies/skill-gate.json"
gate_status=$?
set -e
case "$gate_status" in
  0)
    echo "ALLOW: $REPORT"
    ;;
  10)
    echo "CONDITIONAL: signed owner review is required before installation; report=$REPORT"
    exit 10
    ;;
  *)
    exit "$gate_status"
    ;;
esac
