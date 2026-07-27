"""IDA installation and first-run license diagnostics."""

from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LICENSE_NOT_ACCEPTED_TEXT = "license not yet accepted"
_PROBE_INSTALL_PREFIX = "__IDA_CLI_INSTALL_DIR__="
_PROBE_TIMEOUT_SECONDS = 30.0
_PROBE_CODE = (
    "import idapro\n"
    f"print({_PROBE_INSTALL_PREFIX!r} + str(idapro.get_ida_install_dir()))\n"
)


class IdaLicenseNotAcceptedError(RuntimeError):
    """Raised when IDA refuses headless startup before EULA acceptance."""


@dataclass(frozen=True, slots=True)
class IdaInstallation:
    """Files relevant to one official IDA installation."""

    root: Path | None
    executable: Path | None
    version: str | None
    license_file: Path | None
    license_terms: Path | None
    config_file: Path

    def as_dict(self) -> dict[str, str | None]:
        """Return JSON-compatible installation metadata."""
        return {
            "root": _path_text(self.root),
            "executable": _path_text(self.executable),
            "version": self.version,
            "license_file": _path_text(self.license_file),
            "license_terms": _path_text(self.license_terms),
            "config_file": str(self.config_file),
        }


@dataclass(frozen=True, slots=True)
class IdaProbe:
    """Result of importing idapro in an isolated subprocess."""

    idapro_available: bool
    license_accepted: bool | None
    returncode: int | None
    message: str
    install_dir: Path | None = None

    def as_dict(self) -> dict[str, object]:
        """Return JSON-compatible probe metadata."""
        return {
            "idapro_available": self.idapro_available,
            "license_accepted": self.license_accepted,
            "returncode": self.returncode,
            "message": self.message,
            "install_dir": _path_text(self.install_dir),
        }


def license_not_accepted_message() -> str:
    """Return one actionable message shared by CLI and bridge errors."""
    return (
        "IDA license terms have not been accepted for this user. Run "
        "`ida-ai doctor --fix-license`, review and accept the terms in the official IDA window, "
        "close IDA, then retry the probe. IDA-CLI does not accept the license on the user's behalf."
    )


def text_requires_license_acceptance(text: str) -> bool:
    """Recognize Hex-Rays' stable batch-mode refusal text."""
    return _LICENSE_NOT_ACCEPTED_TEXT in text.casefold()


def exception_requires_license_acceptance(exc: BaseException) -> bool:
    """Search an exception chain for the IDA batch-mode license refusal."""
    current: BaseException | None = exc
    seen: set[int] = set()
    generic_idalib_init_failure = False
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        message = str(current)
        if isinstance(current, IdaLicenseNotAcceptedError) or text_requires_license_acceptance(message):
            return True
        folded = message.casefold()
        generic_idalib_init_failure = generic_idalib_init_failure or (
            "failed to initialize ida library" in folded or "init_library error code" in folded
        )
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    if not generic_idalib_init_failure:
        return False
    return probe_idapro(inspect_ida_installation()).license_accepted is False


def inspect_ida_installation(root: Path | None = None) -> IdaInstallation:
    """Resolve the configured IDA root without importing idapro."""
    config_file = _idapro_config_path()
    selected = root if root is not None else _configured_ida_root(config_file)
    if selected is None:
        selected = _fallback_ida_root()
    executable = _first_existing(
        selected,
        ("ida.exe", "ida64.exe", "ida", "ida64", "ida.app/Contents/MacOS/ida"),
    )
    license_file = _first_existing(selected, ("idapro.hexlic", "ida.hexlic"))
    license_terms = _first_existing(selected, ("license.txt", "LICENSE.txt"))
    return IdaInstallation(
        root=selected,
        executable=executable,
        version=_windows_file_version(executable),
        license_file=license_file,
        license_terms=license_terms,
        config_file=config_file,
    )


def probe_idapro(installation: IdaInstallation) -> IdaProbe:
    """Import idapro in a child so a failed native init cannot poison this CLI."""
    env = os.environ.copy()
    if installation.root is not None:
        env["IDADIR"] = str(installation.root)
        package_dir = installation.root / "idalib" / "python"
        if package_dir.is_dir():
            existing = env.get("PYTHONPATH")
            env["PYTHONPATH"] = str(package_dir) if not existing else str(package_dir) + os.pathsep + existing
    try:
        completed = subprocess.run(
            (sys.executable, "-B", "-c", _PROBE_CODE),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return IdaProbe(True, None, None, f"idapro probe timed out after {_PROBE_TIMEOUT_SECONDS:.0f}s")
    except OSError as exc:
        return IdaProbe(False, None, None, f"could not start idapro probe: {exc}")

    output = _combined_output(completed.stdout, completed.stderr)
    install_dir = _probe_install_dir(output)
    if completed.returncode == 0:
        return IdaProbe(True, True, 0, "idapro initialized successfully", install_dir)
    if text_requires_license_acceptance(output):
        return IdaProbe(True, False, completed.returncode, license_not_accepted_message(), install_dir)
    unavailable = "no module named 'idapro'" in output.casefold() or importlib.util.find_spec("idapro") is None
    message = output[-4096:] if output else f"idapro probe exited with code {completed.returncode}"
    return IdaProbe(not unavailable, None, completed.returncode, message, install_dir)


def run_doctor(*, fix_license: bool = False) -> tuple[int, dict[str, object]]:
    """Diagnose idapro and optionally launch official IDA for first-run acceptance."""
    installation = inspect_ida_installation()
    probe = probe_idapro(installation)
    action = "none"

    if probe.install_dir is not None and probe.install_dir != installation.root:
        installation = inspect_ida_installation(probe.install_dir)

    if fix_license and probe.license_accepted is False:
        executable = installation.executable
        if executable is None:
            return 1, _doctor_payload(
                installation,
                probe,
                action="not_launched",
                status="ida_executable_not_found",
                message="The configured IDA installation has no launchable IDA executable.",
            )
        try:
            subprocess.run((str(executable),), check=False)
        except OSError as exc:
            return 1, _doctor_payload(
                installation,
                probe,
                action="launch_failed",
                status="ida_launch_failed",
                message=f"Could not launch official IDA: {exc}",
            )
        action = "launched_ida"
        probe = probe_idapro(installation)

    if probe.license_accepted is True:
        return 0, _doctor_payload(
            installation,
            probe,
            action=action,
            status="ready",
            message="idapro is ready for headless IDA-CLI sessions.",
        )
    if probe.license_accepted is False:
        return 1, _doctor_payload(
            installation,
            probe,
            action=action,
            status="license_not_accepted",
            message=license_not_accepted_message(),
        )
    status = "probe_failed" if probe.idapro_available else "idapro_unavailable"
    return 1, _doctor_payload(
        installation,
        probe,
        action=action,
        status=status,
        message=probe.message,
    )


def _doctor_payload(
    installation: IdaInstallation,
    probe: IdaProbe,
    *,
    action: str,
    status: str,
    message: str,
) -> dict[str, object]:
    return {
        "status": status,
        "message": message,
        "action": action,
        "installation": installation.as_dict(),
        "probe": probe.as_dict(),
    }


def _idapro_config_path() -> Path:
    idausr = os.environ.get("IDAUSR")
    if idausr:
        return Path(idausr) / "ida-config.json"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    return Path.home() / ".idapro" / "ida-config.json"


def _configured_ida_root(config_file: Path) -> Path | None:
    idadir = os.environ.get("IDADIR")
    if idadir:
        return Path(idadir)
    try:
        data = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    paths = data.get("Paths")
    if not isinstance(paths, dict):
        return None
    value = paths.get("ida-install-dir")
    return Path(value) if isinstance(value, str) and value else None


def _fallback_ida_root() -> Path | None:
    from .kernel import _ida_install_candidates

    for candidate in _ida_install_candidates():
        if _first_existing(candidate, ("ida.exe", "ida64.exe", "ida", "ida64")) is not None:
            return candidate
        if (candidate / "idalib" / "python" / "idapro").is_dir():
            return candidate
    return None


def _first_existing(root: Path | None, relative_paths: tuple[str, ...]) -> Path | None:
    if root is None:
        return None
    for relative in relative_paths:
        candidate = root / relative
        if candidate.exists():
            return candidate
    return None


def _windows_file_version(executable: Path | None) -> str | None:
    if os.name != "nt" or executable is None:
        return None
    try:
        ctypes_api: Any = ctypes
        version_api: Any = ctypes_api.windll.version
        size = int(version_api.GetFileVersionInfoSizeW(str(executable), None))
        if size <= 0:
            return None
        buffer: Any = (ctypes_api.c_byte * size)()
        if not version_api.GetFileVersionInfoW(str(executable), 0, size, buffer):
            return None
        value_pointer = ctypes_api.c_void_p()
        value_length = ctypes_api.c_uint()
        if not version_api.VerQueryValueW(
            buffer,
            "\\",
            ctypes_api.byref(value_pointer),
            ctypes_api.byref(value_length),
        ):
            return None
        values: Any = ctypes_api.cast(
            value_pointer,
            ctypes_api.POINTER(ctypes_api.c_uint32 * 13),
        ).contents
        version_ms = int(values[2])
        version_ls = int(values[3])
        return ".".join(
            str(part)
            for part in (
                version_ms >> 16,
                version_ms & 0xFFFF,
                version_ls >> 16,
                version_ls & 0xFFFF,
            )
        )
    except (AttributeError, OSError, ValueError):
        return None


def _combined_output(stdout: str, stderr: str) -> str:
    return "\n".join(part.strip() for part in (stdout, stderr) if part.strip())


def _probe_install_dir(output: str) -> Path | None:
    for line in output.splitlines():
        if line.startswith(_PROBE_INSTALL_PREFIX):
            value = line.removeprefix(_PROBE_INSTALL_PREFIX).strip()
            return Path(value) if value else None
    return None


def _path_text(path: Path | None) -> str | None:
    return None if path is None else str(path)


__all__ = (
    "IdaInstallation",
    "IdaLicenseNotAcceptedError",
    "IdaProbe",
    "exception_requires_license_acceptance",
    "inspect_ida_installation",
    "license_not_accepted_message",
    "probe_idapro",
    "run_doctor",
    "text_requires_license_acceptance",
)
