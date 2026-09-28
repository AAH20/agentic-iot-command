from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WorkerAPIDeploymentContractTests(unittest.TestCase):
    def test_installer_and_unit_match_and_installer_does_not_activate_service(self):
        installer = (ROOT / "scripts/install-worker-api-linux.sh").read_text(encoding="utf-8")
        unit = (ROOT / "deploy/systemd/a2z-worker-api.service").read_text(encoding="utf-8")
        self.assertIn("/opt/a2z-worker-api", installer)
        self.assertIn("User=a2z-control", unit)
        self.assertIn("Group=a2z-control", unit)
        self.assertIn("WorkingDirectory=/opt/a2z-worker-api", unit)
        self.assertIn("PYTHONPATH=/opt/a2z-worker-api/src", unit)
        self.assertIn("/opt/a2z-worker-api/scripts/worker-api-server.py", unit)
        self.assertIn("/etc/a2z-control-plane/worker-api.json", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=127.0.0.0/8", unit)
        for forbidden_action in ("systemctl start", "systemctl enable", "systemctl daemon-reload", "genpkey"):
            self.assertNotIn(forbidden_action, installer)
        self.assertIn("execution_enabled", installer)
        self.assertIn("is not False", installer)

    def test_installer_copies_verifiers_and_complete_importable_package(self):
        installer = (ROOT / "scripts/install-worker-api-linux.sh").read_text(encoding="utf-8")
        self.assertIn("find \"$ROOT/src/control_plane_core\" -type f -name '*.py'", installer)
        self.assertIn("! -path '*/__pycache__/*'", installer)
        for verifier in ("verify-approval.sh", "verify-autonomy-profile.sh", "verify-impact-assessment.sh",
                         "verify-execution-grant.sh", "verify-runner-attestation.sh"):
            self.assertIn(verifier, installer)

    def test_sample_paths_and_first_runner_scope_match_the_service_contract(self):
        config = json.loads((ROOT / "config/worker-api.example.json").read_text(encoding="utf-8"))
        registry = json.loads((ROOT / "config/worker-identities.example.json").read_text(encoding="utf-8"))
        identity = registry["identities"][0]
        self.assertEqual(config["bind_address"], "127.0.0.1")
        self.assertEqual(config["port"], 9443)
        self.assertEqual(config["signer_socket_path"], "/run/a2z-grant-signer/issuer.sock")
        self.assertEqual(identity["target_ids"], ["00000000-0000-4000-8000-000000000001"])
        self.assertEqual(identity["operation_ids"], ["virtualbox.vm.set_demo_description"])
        self.assertEqual(identity["environments"], ["lab"])


if __name__ == "__main__":
    unittest.main()
