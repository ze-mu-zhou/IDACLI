"""Importable agent snippet for driving IDA-CLI from Codex-like tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ida_cli.agent_bridge import AgentSession


def collect_entry_inventory(target_path: str | Path) -> dict[str, Any]:
    """Collect a small manifest and artifact-backed function inventory."""

    with AgentSession.start(target_path, require_ida=True) as ida:
        backend = ida.probe_backend(require_ida=True)
        manifest = ida.result(
            "__result__ = {'backend': __backend__, 'database_path': __database_path__, 'run_dir': __run_dir__}",
            request_id="session.manifest",
        )
        functions = ida.result("__result__ = ai.export_inventory('inventory')", request_id="inventory.export")
        entries = ida.result("__result__ = ai.entries()", request_id="inventory.entries")
        pwn = ida.result("__result__ = ai.pwn_overview()", request_id="pwn.overview")
    return {"backend": backend, "manifest": manifest, "functions": functions, "entries": entries, "pwn": pwn}
