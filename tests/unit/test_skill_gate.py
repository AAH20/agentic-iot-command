from __future__ import annotations

import datetime as dt
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import skill_gate


ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "policies/skill-gate.json").read_text())


def make_report() -> dict:
    return {
        "risk_assessment": {
            "score": 0,
            "severity": "LOW",
            "max_issue_severity": "NONE",
            "recommendation": "SAFE",
        },
        "analysis_completeness": {
            "is_complete": True,
            "execution_successful": True,
            "total_components": 1,
            "scanned_components": 1,
            "coverage_percent": 100.0,
            "ledger_exceptions": [],
            "analyzer_statuses": [{"status": "completed"}],
        },
        "execution_successful": True,
        "metadata": {"llm_requested": True, "llm_available": True},
        "issues": [],
    }


def make_conditional_report() -> dict:
    report = make_report()
    report["risk_assessment"].update(
        score=8, severity="LOW", max_issue_severity="MEDIUM", recommendation="CAUTION"
    )
    report["issues"].append(
        {
            "finding_id": "finding-privacy-1",
            "id": "SQP-2",
            "severity": "MEDIUM",
            "category": None,
            "tags": [],
        }
    )
    report["analysis_completeness"].update(
        is_complete=False,
        ledger_exceptions=[
            {
                "phase": "reference_resolution",
                "reason_code": "reference_missing",
                "fatal": False,
                "path": "SKILL.md",
                "start_line": 7,
            }
        ],
    )
    return report


class SkillGateTests(unittest.TestCase):
    def test_clean_semantic_report_is_allowed(self) -> None:
        self.assertEqual(skill_gate.evaluate(make_report(), POLICY)[0], "ALLOW")

    def test_medium_caution_and_reference_only_gap_are_conditional(self) -> None:
        self.assertEqual(skill_gate.evaluate(make_conditional_report(), POLICY)[0], "CONDITIONAL")

    def test_high_severity_is_blocked(self) -> None:
        report = make_report()
        report["issues"] = [{"finding_id": "finding-high", "severity": "HIGH"}]
        self.assertEqual(skill_gate.evaluate(report, POLICY)[0], "BLOCK")

    def test_block_categories_are_enforced_even_at_low_severity(self) -> None:
        report = make_report()
        report["issues"] = [{"finding_id": "finding-exfil", "severity": "LOW", "category": "exfiltration"}]
        self.assertEqual(skill_gate.evaluate(report, POLICY)[0], "BLOCK")

    def test_static_only_report_is_blocked(self) -> None:
        report = make_report()
        report["metadata"]["llm_available"] = False
        self.assertEqual(skill_gate.evaluate(report, POLICY)[0], "BLOCK")

    def test_non_reference_incompleteness_is_blocked(self) -> None:
        report = make_report()
        report["analysis_completeness"].update(
            is_complete=False,
            ledger_exceptions=[
                {
                    "phase": "analyzer",
                    "reason_code": "analyzer_runtime_error",
                    "fatal": True,
                    "path": "SKILL.md",
                    "start_line": 1,
                }
            ],
        )
        self.assertEqual(skill_gate.evaluate(report, POLICY)[0], "BLOCK")

    def test_reference_exception_outside_allowlisted_skill_manifest_is_blocked(self) -> None:
        report = make_conditional_report()
        report["analysis_completeness"]["ledger_exceptions"][0]["path"] = "scripts/install.sh"
        self.assertEqual(skill_gate.evaluate(report, POLICY)[0], "BLOCK")

    def test_signed_conditional_review_must_bind_exact_findings_and_exceptions(self) -> None:
        report = make_conditional_report()
        approval_time = dt.datetime.now(dt.timezone.utc)
        exceptions_digest = skill_gate.reference_exception_digest(report)
        envelope = {
            "approval": {
                "artifact_id": "sha256:" + "a" * 64,
                "report_sha256": "b" * 64,
                "owner": "security-owner",
                "approved_at": approval_time.isoformat(),
                "expires_at": (approval_time + dt.timedelta(days=7)).isoformat(),
                "safe_to_install": True,
                "review": {
                    "notes": "Reviewed the report and accepted this bounded test-only integration.",
                    "findings": [
                        {
                            "finding_id": "finding-privacy-1",
                            "severity": "MEDIUM",
                            "mitigation": "Use only public vendor URLs; route confidential pages to self-hosted extraction.",
                        }
                    ],
                    "reference_exceptions_sha256": exceptions_digest,
                },
            },
            "signature": {"algorithm": "ed25519", "key_id": "test-key", "signature_base64": "AA=="},
        }
        skill_gate.validate_approval(report, POLICY, envelope, "a" * 64, "b" * 64)
        envelope["approval"]["review"]["reference_exceptions_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "exact unresolved-reference"):
            skill_gate.validate_approval(report, POLICY, envelope, "a" * 64, "b" * 64)


if __name__ == "__main__":
    unittest.main()
