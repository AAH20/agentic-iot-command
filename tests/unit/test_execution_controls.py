from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from control_plane_core.execution_controls import RootManagedExecutionControl


class RootManagedExecutionControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a2z-execution-controls-")
        self.path = Path(self.temp.name) / "execution-control.json"
        self.control = RootManagedExecutionControl(self.path, require_root_owned=False)

    def tearDown(self):
        self.temp.cleanup()

    def write_control(self, *, enabled, issued_at, expires_at):
        self.path.write_text(json.dumps({
            "schema_version": "a2z-execution-control-v1",
            "execution_enabled": enabled,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "reason": "test fixture",
        }))
        self.path.chmod(0o600)

    def test_installed_disabled_switch_denies_even_with_old_timestamps(self):
        self.write_control(enabled=False, issued_at="1970-01-01T00:00:00Z", expires_at="1970-01-01T00:00:00Z")
        with self.assertRaisesRegex(PermissionError, "kill switch is engaged"):
            self.control.assert_enabled()

    def test_fresh_root_managed_enablement_returns_audit_digest(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.write_control(
            enabled=True,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        )
        self.assertRegex(self.control.assert_enabled(), r"^[0-9a-f]{64}$")

    def test_expired_enablement_and_group_writable_file_fail_closed(self):
        self.write_control(enabled=True, issued_at="2020-01-01T00:00:00Z", expires_at="2020-01-01T00:05:00Z")
        with self.assertRaisesRegex(PermissionError, "expired"):
            self.control.assert_enabled()
        self.path.chmod(0o660)
        with self.assertRaisesRegex(PermissionError, "group-writable"):
            self.control.assert_enabled()


if __name__ == "__main__":
    unittest.main()
