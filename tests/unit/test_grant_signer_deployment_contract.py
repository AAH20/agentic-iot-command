from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class GrantSignerDeploymentContractTests(unittest.TestCase):
    def test_installer_and_systemd_paths_match_and_units_stay_stopped(self):
        installer = (ROOT / "scripts/install-grant-signer-linux.sh").read_text(encoding="utf-8")
        service = (ROOT / "deploy/systemd/a2z-grant-signer.service").read_text(encoding="utf-8")
        socket_unit = (ROOT / "deploy/systemd/a2z-grant-signer.socket").read_text(encoding="utf-8")
        self.assertIn("/opt/a2z-grant-signer", installer)
        self.assertIn("WorkingDirectory=/opt/a2z-grant-signer", service)
        self.assertIn("Environment=PYTHONPATH=/opt/a2z-grant-signer/src", service)
        self.assertIn("/opt/a2z-grant-signer/scripts/grant-signer-server.py", service)
        self.assertIn("/etc/a2z-grant-signer/config.json", service)
        self.assertIn("/run/a2z-grant-signer/issuer.sock", socket_unit)
        for forbidden_action in ("systemctl start", "systemctl enable", "systemctl daemon-reload", "genpkey"):
            self.assertNotIn(forbidden_action, installer)
        self.assertIn("echo \"INFO: no config or key was created", installer)

    def test_signer_service_is_nonroot_networkless_and_readonly(self):
        service = (ROOT / "deploy/systemd/a2z-grant-signer.service").read_text(encoding="utf-8")
        self.assertIn("User=a2z-grant-signer", service)
        self.assertIn("Group=a2z-grant-signer", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadOnlyPaths=/etc/a2z-grant-signer", service)
        self.assertNotIn("AmbientCapabilities=CAP", service)

    def test_installer_copies_python_package_and_exact_scoped_config(self):
        installer = (ROOT / "scripts/install-grant-signer-linux.sh").read_text(encoding="utf-8")
        config = json.loads((ROOT / "config/grant-signer.example.json").read_text(encoding="utf-8"))
        schema = json.loads((ROOT / "schemas/grant-signer-config.schema.json").read_text(encoding="utf-8"))
        self.assertIn("find \"$ROOT/src/control_plane_core\" -type f -name '*.py'", installer)
        self.assertIn("! -path '*/__pycache__/*'", installer)
        self.assertEqual(config["target_ids"], ["00000000-0000-4000-8000-000000000001"])
        self.assertEqual(config["operation_ids"], ["virtualbox.vm.set_demo_description"])
        self.assertEqual(schema["properties"]["target_ids"]["items"]["type"], "string")
        self.assertIn("a2z-control", installer)
        self.assertIn("vboxusers", installer)


if __name__ == "__main__":
    unittest.main()
