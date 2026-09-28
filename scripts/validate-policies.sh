#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import json, pathlib, sys

root = pathlib.Path(sys.argv[1])
skill = json.loads((root / "policies/skill-gate.json").read_text())
runtime = json.loads((root / "policies/runtime-defaults.json").read_text())
schema = json.loads((root / "schemas/skill-approval.schema.json").read_text())
autonomy = json.loads((root / "policies/autonomy-defaults.json").read_text())
autonomy_schema = json.loads((root / "schemas/autonomy-profile.schema.json").read_text())
impact_schema = json.loads((root / "schemas/impact-assessment.schema.json").read_text())

scanner = skill["scanner"]
assert scanner["required"] is True
assert tuple(map(int, scanner["min_version"].split("."))) >= (2, 11, 0)
assert scanner["max_scan_seconds"] > 0
assert scanner["allow_static_only"] is False
assert {"HIGH", "CRITICAL"}.issubset(set(skill["thresholds"]["block_severities"]))
assert skill["approval"]["requires_artifact_digest"] is True
assert skill["approval"]["requires_report_digest"] is True
assert skill["approval"]["requires_expiry"] is True

defaults = runtime["profiles"]["isolated-runner"]
for key in ("secrets", "cloud_credentials", "ssh_agent_forwarding", "browser_profile", "rdp", "production"):
    assert defaults[key] == "deny", f"isolated-runner must deny {key}"
assert defaults["network"] == "deny"
assert runtime["profiles"]["expanded"]["requires_separate_approval"] is True
assert schema["properties"]["signature"]["properties"]["algorithm"]["const"] == "ed25519"
assert autonomy["enabled"] is False and autonomy["rules"] == []
assert autonomy["max_affected_resources"] == 1 and autonomy["max_estimated_cost_microusd"] == 0
assert {"max_affected_resources", "max_estimated_cost_microusd"}.issubset(set(autonomy_schema["required"]))
assert "plan_digest" in impact_schema["properties"]["assessment"]["required"]
assert impact_schema["properties"]["signature"]["properties"]["algorithm"]["const"] == "ed25519"
print("ALLOW: policy baseline is valid")
PY
