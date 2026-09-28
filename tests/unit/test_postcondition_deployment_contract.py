from __future__ import annotations

import json
import re
import unittest
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PostconditionDeploymentContractTests(unittest.TestCase):
    def test_systemd_paths_match_installer_destination(self):
        installer = (ROOT / "scripts/install-postcondition-api-linux.sh").read_text(encoding="utf-8")
        unit = (ROOT / "deploy/systemd/a2z-postcondition-api.service").read_text(encoding="utf-8")
        install_root = re.search(r'^INSTALL_ROOT="([^"]+)"$', installer, re.MULTILINE)
        self.assertIsNotNone(install_root)
        root = install_root.group(1)
        self.assertIn(f"WorkingDirectory={root}", unit)
        self.assertIn(f"Environment=PYTHONPATH={root}/src", unit)
        self.assertIn(f"ExecStart=/usr/bin/python3 {root}/scripts/postcondition-api-server.py", unit)
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=127.0.0.0/8", unit)
        self.assertIn("IPAddressAllow=::1/128", unit)

    def test_tls_sample_paths_match_installer_managed_directory(self):
        installer = (ROOT / "scripts/install-postcondition-api-linux.sh").read_text(encoding="utf-8")
        sample = json.loads((ROOT / "config/postcondition-api.example.json").read_text(encoding="utf-8"))
        tls_dir = re.search(r'^TLS_DIR="([^"]+)"$', installer, re.MULTILINE)
        self.assertIsNotNone(tls_dir)
        for field in ("tls_certificate", "tls_private_key", "client_ca"):
            self.assertTrue(sample[field].startswith(tls_dir.group(1) + "/"), field)

    def test_installer_copies_the_complete_service_import_closure(self):
        installer = (ROOT / "scripts/install-postcondition-api-linux.sh").read_text(encoding="utf-8")
        copied_block = installer.split("for module in \\\n", 1)[1].split("; do", 1)[0]
        installed = set(copied_block.split())
        pending = ["postcondition_server.py"]
        visited: set[str] = set()
        while pending:
            filename = pending.pop()
            if filename in visited:
                continue
            visited.add(filename)
            self.assertIn(filename, installed, f"installer omits imported module {filename}")
            tree = ast.parse((ROOT / "src/control_plane_core" / filename).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                    dependency = f"{node.module.rsplit('.', 1)[-1]}.py"
                    if (ROOT / "src/control_plane_core" / dependency).is_file():
                        pending.append(dependency)


if __name__ == "__main__":
    unittest.main()
