"""Tests for backend session assembly without requiring IDA."""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli import kernel
from ida_cli.doctor import IdaLicenseNotAcceptedError
from ida_cli.kernel import BackendInfo, IdaLibBackend, KernelError, PythonOnlyBackend, create_session


class FailingBackend:
    """Backend that raises a deterministic startup error."""

    def open(self, _target_path: str) -> BackendInfo:
        raise KernelError("backend failed")


class FakeIdaPro:
    """Tiny idapro-shaped stub for backend contract tests."""

    def __init__(self, *, open_status: object = 0, open_error: BaseException | None = None) -> None:
        self._open_status = open_status
        self._open_error = open_error
        self.open_calls: list[tuple[str, bool]] = []
        self.close_calls: list[bool] = []

    def open_database(self, target_path: str, auto_analysis: bool) -> object:
        self.open_calls.append((target_path, auto_analysis))
        if self._open_error is not None:
            raise self._open_error
        return self._open_status

    def close_database(self, save_changes: bool) -> None:
        self.close_calls.append(save_changes)


class KernelTests(unittest.TestCase):
    """Exercise session construction and backend metadata."""

    def setUp(self) -> None:
        kernel._CACHED_IDA_ROOT = None

    def test_python_backend_metadata_is_explicit(self) -> None:
        backend = PythonOnlyBackend()

        info = backend.open("sample.i64")

        self.assertFalse(info.ida_available)
        self.assertFalse(info.database_opened)
        self.assertEqual(info.name, "python")
        self.assertIn("Python-only", info.message)

    def test_create_session_wires_runtime_artifacts_and_backend_globals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session = create_session("sample.i64", runs_dir=Path(temp_dir) / "runs", backend=PythonOnlyBackend())

            response = session.runtime.execute(
                "__result__ = {'backend': __backend__['name'], 'has_store': __artifact_store__ is not None}"
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["result"], {"backend": "python", "has_store": True})

    def test_create_session_rejects_empty_target(self) -> None:
        with self.assertRaises(KernelError):
            create_session("", backend=PythonOnlyBackend())

    def test_backend_startup_error_is_not_hidden(self) -> None:
        with self.assertRaises(KernelError):
            create_session("sample.i64", backend=FailingBackend())

    def test_local_ida_install_path_is_discovered_without_global_pip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "IDA"
            package = root / "idalib" / "python" / "idapro"
            package.mkdir(parents=True)

            with mock.patch.object(kernel, "_idapro_importable", return_value=False):
                with mock.patch.object(kernel, "_ida_install_candidates", return_value=(root,)):
                    with mock.patch.dict(os.environ, {"IDADIR": "C:/stale-ida"}, clear=True):
                        original_path = list(sys.path)
                        try:
                            kernel._prepare_idalib_import_path()
                            self.assertEqual(os.environ["IDADIR"], str(root))
                            self.assertEqual(sys.path[0], str(root / "idalib" / "python"))
                        finally:
                            sys.path[:] = original_path

    def test_recursive_drive_scan_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            drive = Path(temp_dir)
            root = drive / "Reverse" / "IDA 9.1"
            package = root / "idalib" / "python" / "idapro"
            package.mkdir(parents=True)

            with mock.patch.object(kernel, "_idapro_importable", return_value=False):
                with mock.patch.object(kernel, "_ida_install_candidates", return_value=()):
                    with mock.patch.object(kernel, "_local_drive_roots", return_value=(drive,)):
                        with mock.patch.dict(os.environ, {}, clear=True):
                            original_path = list(sys.path)
                            try:
                                kernel._prepare_idalib_import_path()
                                self.assertNotIn(str(root / "idalib" / "python"), sys.path)
                                os.environ[kernel._DEEP_DISCOVERY_ENV] = "1"
                                kernel._prepare_idalib_import_path()
                                self.assertEqual(os.environ["IDADIR"], str(root))
                                self.assertEqual(sys.path[0], str(root / "idalib" / "python"))
                            finally:
                                sys.path[:] = original_path

    def test_idalib_backend_accepts_zero_status_and_closes_database(self) -> None:
        fake = FakeIdaPro(open_status=0)
        backend = IdaLibBackend(fake)

        with mock.patch.object(kernel, "_prepare_idalib_import_path"):
            with mock.patch.object(kernel, "_wait_for_auto_analysis"):
                session = create_session("sample.i64", backend=backend)

        self.assertEqual(session.backend_info.name, "idalib")
        self.assertTrue(session.backend_info.database_opened)
        self.assertEqual(fake.open_calls, [("sample.i64", True)])

        session.close()

        self.assertEqual(fake.close_calls, [False])

    def test_idalib_backend_rejects_nonzero_open_database_status(self) -> None:
        fake = FakeIdaPro(open_status=13)
        backend = IdaLibBackend(fake)

        with mock.patch.object(kernel, "_prepare_idalib_import_path"):
            with mock.patch.object(kernel, "_wait_for_auto_analysis"):
                with self.assertRaisesRegex(KernelError, "error code 13"):
                    backend.open("sample.i64")

    def test_idalib_backend_classifies_license_acceptance_failure(self) -> None:
        fake = FakeIdaPro(open_error=RuntimeError("License not yet accepted, cannot run in batch mode"))
        backend = IdaLibBackend(fake)

        with mock.patch.object(kernel, "_prepare_idalib_import_path"):
            with self.assertRaisesRegex(IdaLicenseNotAcceptedError, "doctor --fix-license"):
                backend.open("sample.i64")

    def test_wait_for_auto_analysis_rejects_false(self) -> None:
        ida_auto = types.SimpleNamespace(auto_wait=lambda: False)

        with mock.patch.object(kernel.importlib, "import_module", return_value=ida_auto):
            with self.assertRaisesRegex(KernelError, "incomplete analysis state"):
                kernel._wait_for_auto_analysis()

    def test_session_close_swallows_backend_close_failure(self) -> None:
        """A failing backend close must never escape KernelSession.close()."""

        class CloseFails(PythonOnlyBackend):
            def close(self) -> None:
                raise KernelError("close failed")

        with tempfile.TemporaryDirectory() as temp_dir:
            session = create_session("sample.i64", runs_dir=Path(temp_dir) / "runs", backend=CloseFails())
            session.close()
            session.close()

        self.assertTrue(session.closed)

    def test_create_session_cleanup_failure_does_not_mask_primary_error(self) -> None:
        """A close failure during startup cleanup must not hide the real error."""

        class CloseFails(PythonOnlyBackend):
            def close(self) -> None:
                raise KernelError("close failed")

        with mock.patch.object(kernel.ArtifactStore, "create", side_effect=RuntimeError("store broke")):
            with self.assertRaisesRegex(RuntimeError, "store broke"):
                create_session("sample.i64", backend=CloseFails())

    def test_open_cleanup_close_failure_does_not_mask_analysis_error(self) -> None:
        """A close failure after a failed auto-analysis must not hide it."""

        class ExplodingCloseIdaPro(FakeIdaPro):
            def close_database(self, save_changes: bool) -> None:
                raise RuntimeError("close exploded")

        backend = IdaLibBackend(ExplodingCloseIdaPro(open_status=0))
        with mock.patch.object(kernel, "_prepare_idalib_import_path"):
            with mock.patch.object(kernel, "_wait_for_auto_analysis", side_effect=KernelError("analysis broke")):
                with self.assertRaisesRegex(KernelError, "analysis broke"):
                    backend.open("sample.i64")

    def test_idalib_available_checks_importability_without_importing(self) -> None:
        """available() must answer via find_spec, not a full idapro import."""
        with mock.patch.object(kernel, "_prepare_idalib_import_path"):
            with mock.patch.object(kernel, "_idapro_importable", return_value=True):
                self.assertTrue(IdaLibBackend.available())
            with mock.patch.object(kernel, "_idapro_importable", return_value=False):
                self.assertFalse(IdaLibBackend.available())

    @unittest.skipUnless(os.name == "nt", "drive enumeration is Windows-only")
    def test_local_drive_roots_uses_win32_enumeration(self) -> None:
        """Windows drive roots come from Win32, not blocking path probes."""
        with mock.patch.object(kernel, "_win32_fixed_drive_roots", return_value=(Path("C:/"),)) as enum:
            roots = kernel._local_drive_roots()

        enum.assert_called_once_with()
        self.assertEqual(roots, (Path("C:/"),))

    @unittest.skipUnless(os.name == "nt", "drive enumeration is Windows-only")
    def test_local_drive_roots_returns_only_existing_roots(self) -> None:
        roots = kernel._local_drive_roots()

        self.assertTrue(roots)
        for root in roots:
            self.assertTrue(root.exists(), root)

    def test_local_drive_roots_falls_back_to_probing_when_win32_fails(self) -> None:
        """Any Win32 enumeration failure falls back to safe per-drive probes."""
        if os.name == "nt":
            with mock.patch.object(kernel, "_win32_fixed_drive_roots", side_effect=OSError("no win32")):
                roots = kernel._local_drive_roots()
        else:
            roots = kernel._local_drive_roots()
        self.assertTrue(all(root.exists() for root in roots))


if __name__ == "__main__":
    unittest.main()
