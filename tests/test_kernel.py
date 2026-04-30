"""Tests for backend session assembly without requiring IDA."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli.kernel import BackendInfo, KernelError, PythonOnlyBackend, create_session
from ida_cli import kernel


class FailingBackend:
    """Backend that raises a deterministic startup error."""

    def open(self, _target_path: str) -> BackendInfo:
        raise KernelError("backend failed")


class KernelTests(unittest.TestCase):
    """Exercise session construction and backend metadata."""

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

            with mock.patch.object(kernel, "_ida_install_candidates", return_value=(root,)):
                with mock.patch.dict(os.environ, {}, clear=True):
                    original_path = list(sys.path)
                    try:
                        kernel._prepare_idalib_import_path()
                        self.assertEqual(os.environ["IDADIR"], str(root))
                        self.assertEqual(sys.path[0], str(root / "idalib" / "python"))
                    finally:
                        sys.path[:] = original_path


if __name__ == "__main__":
    unittest.main()
