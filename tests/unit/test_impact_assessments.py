from __future__ import annotations

import base64
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from control_plane_core.impact_assessments import ImpactAssessmentVerifier


class MockVerifier(ImpactAssessmentVerifier):
    def _verify_signature(self, envelope):
        self.signature_verified = True


class ImpactAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-impact-assessment-test-")
        self.verifier = MockVerifier(Path(self.temp.name), require_root_owned_trust=False)
        self.now = dt.datetime(2026, 9, 23, 12, tzinfo=dt.timezone.utc)
        self.assessment = {
            "schema_version": "a2z-impact-assessment-v1",
            "assessment_id": str(uuid4()),
            "tenant_id": "lab",
            "task_id": str(uuid4()),
            "operation_id": "virtualbox.vm.start",
            "target_ids": ["vm-lab-1"],
            "environment": "lab",
            "plan_digest": "a" * 64,
            "affected_resource_count": 1,
            "estimated_cost_microusd": 2500,
            "source_id": "plan-analyzer-lab",
            "generated_at": "2026-09-23T11:59:00Z",
            "expires_at": "2026-09-23T12:05:00Z",
        }
        self.envelope = {
            "assessment": self.assessment,
            "signature": {
                "algorithm": "ed25519", "key_id": "lab-estimator-v1",
                "signature_base64": base64.b64encode(b"s" * 64).decode("ascii"),
            },
        }
        self.expected = {
            "tenant_id": "lab", "task_id": self.assessment["task_id"],
            "operation_id": "virtualbox.vm.start", "target_ids": ("vm-lab-1",),
            "environment": "lab", "plan_digest": "a" * 64,
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_verified_assessment_returns_exact_plan_bound_cost_and_scope(self):
        result = self.verifier.verify(self.envelope, expected=self.expected, now=self.now)
        self.assertEqual(result.estimated_cost_microusd, 2500)
        self.assertEqual(result.affected_resource_count, 1)
        self.assertEqual(result.plan_digest, "a" * 64)
        self.assertRegex(result.assessment_digest, r"^[0-9a-f]{64}$")
        self.assertTrue(self.verifier.signature_verified)

    def test_mismatched_plan_or_target_and_stale_assessment_are_rejected(self):
        with self.assertRaisesRegex(PermissionError, "plan_digest"):
            self.verifier.verify(self.envelope, expected={**self.expected, "plan_digest": "b" * 64}, now=self.now)
        with self.assertRaisesRegex(PermissionError, "target_ids"):
            self.verifier.verify(self.envelope, expected={**self.expected, "target_ids": ("other-vm",)}, now=self.now)
        with self.assertRaisesRegex(PermissionError, "not currently valid"):
            self.verifier.verify(self.envelope, expected=self.expected,
                                 now=dt.datetime(2026, 9, 23, 12, 6, tzinfo=dt.timezone.utc))

    def test_wildcard_targets_and_boolean_cost_values_are_rejected(self):
        self.assessment["target_ids"] = ["*"]
        with self.assertRaisesRegex(ValueError, "target_ids"):
            self.verifier.verify(self.envelope, expected={**self.expected, "target_ids": ("*",)}, now=self.now)
        self.assessment["target_ids"] = ["vm-lab-1"]
        self.assessment["estimated_cost_microusd"] = True
        with self.assertRaisesRegex(ValueError, "estimated_cost_microusd"):
            self.verifier.verify(self.envelope, expected=self.expected, now=self.now)

    def test_oversized_envelope_is_rejected_before_signature_verification(self):
        self.envelope["signature"]["signature_base64"] = "A" * 90_000
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            self.verifier.verify(self.envelope, expected=self.expected, now=self.now)
        self.assertFalse(getattr(self.verifier, "signature_verified", False))


if __name__ == "__main__":
    unittest.main()
