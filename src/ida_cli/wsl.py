"""WSL adaptation layer — auto-detect and bridge between WSL and Windows IDA.

This module is Agent-only: no human interaction, no prompts, no fallback dialogs.
All failures raise clear exceptions with actionable messages.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_ENV_PYTHON = "IDA_CLI_PYTHON"
_WSL_INTEROP = "/proc/sys/fs/binfmt_misc/WSLInterop"


def is_wsl() -> bool:
    """Return True when running Linux Python under WSL."""
    return Path(_WSL_INTEROP).is_file()


def find_ida_python() -> str:
    """Return absolute path to a Windows python.exe that can import idapro.

    Search order:
      1. IDA_CLI_PYTHON env var (explicit override)
      2. D:\\Python* and C:\\Python* prefix scan
      3. Raise RuntimeError with actionable message
    """
    explicit = os.environ.get(_ENV_PYTHON)
    if explicit:
        path = _check_python(explicit)
        if path:
            return path
        raise RuntimeError(
            f"{_ENV_PYTHON}={explicit!r} cannot import idapro. "
            "Verify: that python.exe has 'idapro' installed (pip list | findstr idapro)."
        )

    for candidate in _scan_python_candidates():
        path = _check_python(candidate)
        if path:
            return path

    raise RuntimeError(
        "No Windows Python with idapro found. Install idapro:\n"
        "  cd <IDA_ROOT>\\idalib\\python\n"
        "  python -m pip install idapro\n"
        "  python py-activate-idalib.py\n"
        f"Or set {_ENV_PYTHON}=C:\\path\\to\\python.exe"
    )


def wsl_to_win(wsl_path: str) -> str:
    """Convert WSL path to Windows path: /mnt/d/pwn/pwn -> D:\\pwn\\pwn."""
    try:
        result = subprocess.run(
            ["wslpath", "-w", wsl_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return _fallback_wsl_to_win(wsl_path)


def win_to_wsl(win_path: str) -> str:
    """Convert Windows path to WSL path: D:\\pwn\\pwn -> /mnt/d/pwn/pwn."""
    try:
        result = subprocess.run(
            ["wslpath", "-u", win_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return _fallback_win_to_wsl(win_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_python(python_exe: str) -> str | None:
    """Return python_exe if it can import idapro, else None."""
    try:
        result = subprocess.run(
            [python_exe, "-c", "import idapro"],
            capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            return python_exe
    except Exception:
        pass
    return None


def _scan_python_candidates() -> list[str]:
    """Yield potential Windows python.exe paths under common roots."""
    candidates: list[str] = []
    for drive in ("D", "C"):
        root = Path(f"/mnt/{drive.lower()}")
        if not root.is_dir():
            continue
        # Direct Python installs: D:\Python311\python.exe
        for py_dir in sorted(root.glob("Python*"), reverse=True):
            exe = py_dir / "python.exe"
            if exe.is_file():
                candidates.append(str(exe))
        # %LOCALAPPDATA% style: D:\Python\bin\python.exe (store/WSL paths)
        for layout in ("Python", "Program Files/Python"):
            for py_dir in sorted(root.glob(f"{layout}/*"), reverse=True):
                exe = py_dir / "python.exe"
                if exe.is_file():
                    candidates.append(str(exe))
    return candidates


def _fallback_wsl_to_win(wsl_path: str) -> str:
    """Best-effort WSL-to-Win conversion without wslpath."""
    p = Path(wsl_path)
    parts = p.parts
    if len(parts) >= 3 and parts[0] == "/" and parts[1] == "mnt":
        drive = parts[2].upper()
        tail = "\\".join(parts[3:])
        return f"{drive}:\\{tail}"
    return wsl_path


def _fallback_win_to_wsl(win_path: str) -> str:
    """Best-effort Win-to-WSL conversion without wslpath."""
    if len(win_path) >= 2 and win_path[1] == ":":
        drive = win_path[0].lower()
        tail = win_path[3:].replace("\\", "/")
        return f"/mnt/{drive}/{tail}"
    return win_path
