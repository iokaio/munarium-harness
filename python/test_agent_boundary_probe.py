# SPDX-License-Identifier: Apache-2.0
"""Regress the credential-access oracle independently of native composition tests."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("agent_probe", Path(__file__).resolve().parents[1] / "tests/network/agent_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class CredentialProbe(unittest.TestCase):
    def test_readable_credential_is_not_a_denied_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fictional-credential"
            path.write_bytes(b"synthetic-test-only")
            self.assertFalse(probe.inaccessible(path))
            self.assertTrue(probe.inaccessible(Path(directory) / "absent"))

    def test_permission_denial_is_a_denied_path(self):
        with patch.object(Path, "open", side_effect=PermissionError):
            self.assertTrue(probe.inaccessible("synthetic-unreadable"))

    def test_unexpected_filesystem_failure_cannot_pass(self):
        with patch.object(Path, "open", side_effect=OSError("synthetic I/O error")):
            with self.assertRaises(OSError):
                probe.inaccessible("synthetic-failure")


if __name__ == "__main__":
    unittest.main()
