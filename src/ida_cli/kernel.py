"""Backend lifecycle for the unrestricted IDA CLI runtime."""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ai_helpers import AIHelpers
from .artifacts import ArtifactStore
from .runtime import PythonRuntime


class KernelError(RuntimeError):
    """Raised when the kernel cannot satisfy an exact backend operation."""


@dataclass(frozen=True, slots=True)
class BackendInfo:
    """JSON-compatible backend status exposed to the AI runtime."""

    name: str
    target_path: str
    database_opened: bool
    ida_available: bool
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Return protocol-ready metadata for runtime globals."""
        return {
            "name": self.name,
            "target_path": self.target_path,
            "database_opened": self.database_opened,
            "ida_available": self.ida_available,
            "message": self.message,
        }


@dataclass(slots=True)
class KernelSession:
    """Own one backend, artifact store, helper object, and Python runtime."""

    target_path: str
    backend_info: BackendInfo
    artifact_store: ArtifactStore
    ai: AIHelpers
    runtime: PythonRuntime

    def close(self) -> None:
        """Close backend-owned resources; current backends need no shutdown work."""


class PythonOnlyBackend:
    """Protocol-test backend that does not import IDA or open databases."""

    name = "python"

    def open(self, target_path: str) -> BackendInfo:
        """Expose a transparent non-IDA backend for protocol/runtime operation."""
        return BackendInfo(
            name=self.name,
            target_path=target_path,
            database_opened=False,
            ida_available=False,
            message="idapro is unavailable; running Python-only kernel",
        )


class IdaLibBackend:
    """Minimal idalib backend using Hex-Rays' `idapro` module when available."""

    name = "idalib"

    def __init__(self, idapro: Any | None = None) -> None:
        """Allow tests to inject an idapro-shaped object without importing IDA."""
        self._idapro = idapro

    @classmethod
    def available(cls) -> bool:
        """Return whether the `idapro` module can be imported now."""
        _prepare_idalib_import_path()
        try:
            importlib.import_module("idapro")
        except ModuleNotFoundError:
            return False
        return True

    def open(self, target_path: str) -> BackendInfo:
        """Open the target database through idalib and wait for auto-analysis."""
        _prepare_idalib_import_path()
        idapro = self._idapro if self._idapro is not None else importlib.import_module("idapro")
        try:
            opened = idapro.open_database(target_path, True)
        except Exception as exc:
            raise KernelError(f"idapro.open_database failed for {target_path!r}: {exc}") from exc
        if opened is False:
            raise KernelError(f"idapro.open_database returned false for {target_path!r}")
        _wait_for_auto_analysis()
        return BackendInfo(
            name=self.name,
            target_path=target_path,
            database_opened=True,
            ida_available=True,
        )


def create_session(
    target_path: str | os.PathLike[str],
    *,
    runs_dir: str | os.PathLike[str] = "runs",
    backend: Any | None = None,
) -> KernelSession:
    """Create one long-lived Python runtime session for the target."""
    target = _target_text(target_path)
    selected = _select_backend() if backend is None else backend
    backend_info = selected.open(target)
    artifact_store = ArtifactStore.create(runs_dir)
    ai = AIHelpers(artifact_store.artifact_dir)
    initial_globals = _ida_modules()
    initial_globals.update(
        {
            "__artifact_store__": artifact_store,
            "__backend__": backend_info.as_dict(),
        }
    )
    runtime = PythonRuntime(
        initial_globals=initial_globals,
        ai=ai,
        database_path=target,
        run_dir=str(artifact_store.run_dir),
    )
    return KernelSession(
        target_path=target,
        backend_info=backend_info,
        artifact_store=artifact_store,
        ai=ai,
        runtime=runtime,
    )


def _select_backend() -> Any:
    """Select idalib when present; otherwise expose the transparent Python backend."""
    if IdaLibBackend.available():
        return IdaLibBackend()
    return PythonOnlyBackend()


def _prepare_idalib_import_path() -> None:
    """Expose bundled `idapro` for common local IDA installations."""
    for root in _ida_install_candidates():
        package_dir = root / "idalib" / "python"
        if (package_dir / "idapro").is_dir():
            if str(package_dir) not in sys.path:
                sys.path.insert(0, str(package_dir))
            os.environ.setdefault("IDADIR", str(root))
            return


def _ida_install_candidates() -> tuple[Path, ...]:
    """Return IDA roots worth probing without requiring registry access."""
    candidates: list[Path] = []
    env_root = os.environ.get("IDADIR")
    if env_root:
        candidates.append(Path(env_root))
    candidates.append(Path("D:/IDA"))
    return tuple(candidates)


def _target_text(target_path: str | os.PathLike[str]) -> str:
    """Validate and normalize a target path string without requiring existence."""
    target = os.fspath(target_path)
    if not target:
        raise KernelError("target path must not be empty")
    return str(Path(target))


def _wait_for_auto_analysis() -> None:
    """Wait for IDA auto-analysis when the module exists in the backend runtime."""
    try:
        ida_auto = importlib.import_module("ida_auto")
    except ModuleNotFoundError:
        return
    if hasattr(ida_auto, "auto_wait"):
        ida_auto.auto_wait()


def _ida_modules() -> dict[str, Any]:
    """Pre-import common IDAPython modules when they are available."""
    modules: dict[str, Any] = {}
    for name in (
        "idaapi",
        "idautils",
        "idc",
        "ida_auto",
        "ida_bytes",
        "ida_entry",
        "ida_funcs",
        "ida_gdl",
        "ida_hexrays",
        "ida_name",
        "ida_nalt",
        "ida_segment",
        "ida_typeinf",
        "ida_xref",
    ):
        try:
            modules[name] = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    return modules


__all__ = (
    "BackendInfo",
    "IdaLibBackend",
    "KernelError",
    "KernelSession",
    "PythonOnlyBackend",
    "create_session",
)
