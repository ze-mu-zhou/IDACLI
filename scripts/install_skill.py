"""Install IDA-CLI skills for Codex, Kimi Code, Claude Code, and Reasonix."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

_SKILL_NAME = "ida-cli"
_AGENTS = ("codex", "kimi", "claude", "reasonix")


class InstallError(RuntimeError):
    """Raised when a skill cannot be installed exactly."""


def main(argv: list[str] | None = None) -> int:
    """Install requested skill flavor and print one JSON result."""

    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = install(args.agent, target_root=args.target_root, force=args.force)
        exit_code = 0
    except Exception as exc:  # noqa: BLE001 - CLI must serialize unexpected installer failures.
        result = {"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}}
        exit_code = 1
    print(json.dumps(result, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return exit_code


def install(agent: str, *, target_root: str | os.PathLike[str] | None = None, force: bool = False) -> dict[str, object]:
    """Install one or all skill flavors."""

    agents = _AGENTS if agent == "all" else (agent,)
    installed = [
        _install_one(item, target_root=_target_root_for_all(target_root, item) if agent == "all" else target_root, force=force)
        for item in agents
    ]
    return {"ok": True, "installed": installed}


def _install_one(agent: str, *, target_root: str | os.PathLike[str] | None, force: bool) -> dict[str, str]:
    """Install one agent flavor, refusing destinations that collide with the source."""
    if agent not in _AGENTS:
        raise InstallError(f"unsupported agent: {agent}")
    source = _repo_root() / "skills" / agent / _SKILL_NAME
    if not source.is_dir():
        raise InstallError(f"missing source skill: {source}")
    root = Path(target_root) if target_root is not None else _default_root(agent)
    destination = root / _SKILL_NAME
    # resolve() folds symlinks and ".." spellings; normcase() folds case so
    # differing spellings compare equal on case-insensitive filesystems.
    resolved_source = Path(os.path.normcase(source.resolve()))
    resolved_destination = Path(os.path.normcase(destination.resolve()))
    if resolved_destination == resolved_source or resolved_source in resolved_destination.parents:
        raise InstallError(f"destination conflicts with source skill directory: {destination}")
    if destination.exists():
        if not force:
            raise InstallError(f"destination exists; rerun with --force: {destination}")
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    return {"agent": agent, "source": str(source), "destination": str(destination)}


def _default_root(agent: str) -> Path:
    if agent == "codex":
        home = os.environ.get("CODEX_HOME")
        return (Path(home) if home else Path.home() / ".codex") / "skills"
    if agent == "kimi":
        home = os.environ.get("KIMI_CODE_HOME")
        return (Path(home) if home else Path.home() / ".kimi-code") / "skills"
    if agent == "claude":
        home = os.environ.get("CLAUDE_CONFIG_DIR")
        return (Path(home) if home else Path.home() / ".claude") / "skills"
    if agent == "reasonix":
        home = os.environ.get("REASONIX_HOME")
        if home:
            return Path(home) / "skills"
        if os.name == "nt":
            appdata = os.environ.get("APPDATA")
            return (Path(appdata) if appdata else Path.home() / "AppData" / "Roaming") / "reasonix" / "skills"
        return Path.home() / ".reasonix" / "skills"
    raise InstallError(f"unsupported agent: {agent}")


def _target_root_for_all(target_root: str | os.PathLike[str] | None, agent: str) -> Path | None:
    if target_root is None:
        return None
    return Path(target_root) / agent


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install IDA-CLI skills for Codex, Kimi Code, Claude Code, and Reasonix.")
    parser.add_argument("agent", choices=(*_AGENTS, "all"))
    parser.add_argument("--target-root", help="Override destination skills root for the selected agent.")
    parser.add_argument("--force", action="store_true", help="Replace an existing ida-cli skill directory.")
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
