from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROBE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "a2z-readonly-probe"
PROBE = runpy.run_path(str(PROBE_PATH))


class ReadOnlyProbeTests(unittest.TestCase):
    def test_user_controlled_vboxmanage_binary_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="a2z-untrusted-vbox-") as directory:
            executable = Path(directory) / "VBoxManage"
            executable.write_text("not executed")
            executable.chmod(0o755)
            with patch.object(PROBE["shutil"], "which", return_value=str(executable)):
                with self.assertRaisesRegex(PermissionError, "outside trusted system directories"):
                    PROBE["trusted_vboxmanage"]()

    def test_unavailable_vboxmanage_is_reported_without_execution(self):
        with patch.object(PROBE["shutil"], "which", return_value=None):
            self.assertIsNone(PROBE["trusted_vboxmanage"]())


if __name__ == "__main__":
    unittest.main()
