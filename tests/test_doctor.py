"""Tests for IDA installation and first-run license diagnostics."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli import doctor
from ida_cli.doctor import IdaInstallation, IdaProbe


class DoctorTests(unittest.TestCase):
    """Keep license repair explicit and all detection side-effect free."""

    def test_inspect_uses_official_idapro_config_without_importing_idapro(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            user_dir = base / "user"
            root = base / "IDA"
            user_dir.mkdir()
            root.mkdir()
            (root / "ida.exe").touch()
            (root / "idapro.hexlic").touch()
            (root / "license.txt").touch()
            (user_dir / "ida-config.json").write_text(
                json.dumps({"Paths": {"ida-install-dir": str(root)}}),
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"IDAUSR": str(user_dir)}, clear=True):
                with mock.patch.object(doctor, "_windows_file_version", return_value="9.3.26.213"):
                    installation = doctor.inspect_ida_installation()

        self.assertEqual(installation.root, root)
        self.assertEqual(installation.executable, root / "ida.exe")
        self.assertEqual(installation.version, "9.3.26.213")
        self.assertEqual(installation.license_file, root / "idapro.hexlic")
        self.assertEqual(installation.license_terms, root / "license.txt")

    def test_probe_recognizes_license_refusal_from_child_output(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[sys.executable],
            returncode=1,
            stdout="",
            stderr="License not yet accepted, cannot run in batch mode",
        )
        installation = IdaInstallation(None, None, None, None, None, Path("ida-config.json"))

        with mock.patch.object(doctor.subprocess, "run", return_value=completed):
            with mock.patch.object(doctor.importlib.util, "find_spec", return_value=object()):
                probe = doctor.probe_idapro(installation)

        self.assertTrue(probe.idapro_available)
        self.assertFalse(probe.license_accepted)
        self.assertIn("doctor --fix-license", probe.message)

    def test_generic_idalib_init_error_uses_isolated_probe_for_classification(self) -> None:
        installation = IdaInstallation(Path("D:/IDA"), None, None, None, None, Path("x"))
        probe = IdaProbe(True, False, 1, doctor.license_not_accepted_message())
        error = ImportError("Failed to initialize IDA library, init_library error code 1")

        with mock.patch.object(doctor, "inspect_ida_installation", return_value=installation):
            with mock.patch.object(doctor, "probe_idapro", return_value=probe) as isolated_probe:
                requires_acceptance = doctor.exception_requires_license_acceptance(error)

        self.assertTrue(requires_acceptance)
        isolated_probe.assert_called_once_with(installation)

    def test_fix_license_launches_official_ida_then_retries_probe(self) -> None:
        installation = IdaInstallation(
            Path("D:/IDA"),
            Path("D:/IDA/ida.exe"),
            "9.3",
            Path("D:/IDA/idapro.hexlic"),
            Path("D:/IDA/license.txt"),
            Path("ida-config.json"),
        )
        before = IdaProbe(True, False, 1, doctor.license_not_accepted_message())
        after = IdaProbe(True, True, 0, "idapro initialized successfully", Path("D:/IDA"))

        with mock.patch.object(doctor, "inspect_ida_installation", return_value=installation):
            with mock.patch.object(doctor, "probe_idapro", side_effect=(before, after)) as probe:
                with mock.patch.object(doctor.subprocess, "run") as launch:
                    exit_code, payload = doctor.run_doctor(fix_license=True)

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["action"], "launched_ida")
        launch.assert_called_once_with((str(installation.executable),), check=False)
        self.assertEqual(probe.call_count, 2)

    def test_fix_license_does_not_launch_ida_for_unrelated_probe_failure(self) -> None:
        installation = IdaInstallation(Path("D:/IDA"), Path("D:/IDA/ida.exe"), None, None, None, Path("x"))
        probe = IdaProbe(True, None, 1, "unrelated native failure")

        with mock.patch.object(doctor, "inspect_ida_installation", return_value=installation):
            with mock.patch.object(doctor, "probe_idapro", return_value=probe):
                with mock.patch.object(doctor.subprocess, "run") as launch:
                    exit_code, payload = doctor.run_doctor(fix_license=True)

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "probe_failed")
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
