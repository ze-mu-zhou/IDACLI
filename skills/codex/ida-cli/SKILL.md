---
name: ida-cli
description: Use this skill when Codex needs to drive local IDA Pro or Hex-Rays through the IDA-CLI AI-only JSONL kernel, integrate IDA with Codex or Claude Code style agents, run IDAPython/idalib analysis from a CLI subprocess, collect artifacts, use AI helper APIs, persist caches, merge mutation records, or inspect binaries without opening IDA GUI panels.
---

# IDA-CLI

Use the repository that contains `pyproject.toml` with project name `ida-cli`.
The runtime is AI-only: one target argument, stdin JSONL requests, stdout JSONL
responses, unrestricted Python execution, persistent globals, and artifact-
backed large outputs.

The supported IDA surface is `IDA Pro 9.0+` simple-open idalib workflows. This
skill does not expose the extra loader-argument variants that IDA 9.1/9.2 added
to `open_database()`.

## Install Runtime

From the repository root:

```powershell
cd <IDA_ROOT>\idalib\python
python -m pip install idapro
python py-activate-idalib.py

cd <IDA_CLI_REPO>
python -m pip install -e .
```

IDA-CLI probes an already importable `idapro` first. If that official setup was
skipped, the runtime next checks `IDADIR` and bounded Windows install layouts.
Full-drive discovery is slow and off by default; opt into it with
`IDA_CLI_DEEP_IDA_DISCOVERY=1` only as a last resort.

## Agent Bridge

Prefer the importable bridge for Codex tool runs:

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start("path/to/target.i64", require_ida=True) as ida:
    backend = ida.probe_backend(require_ida=True)
    funcs = ida.result("__result__ = ai.functions()", request_id="inventory.functions")
```

Keep one `AgentSession` alive for an analysis pass so IDA auto-analysis,
globals, imports, and caches are reused.
`AgentSession` validates response IDs, rejects non-strict JSON responses, and
times out hung requests by default; pass `timeout_s=` per request for known slow
decompiler work.

## Protocol

Every request is one strict JSON object with a `code` string and optional `id`.
The runtime executes `exec(code, globals_env, globals_env)` and serializes
`__result__`. Python stdout/stderr are captured into response fields.

## Required First Probe

For IDA work, probe `__backend__` first and require `ida_available`:

```python
backend = ida.probe_backend(require_ida=True)
```

Python-only mode is useful for protocol tests but is not binary analysis.

## Common Workflows

Pwn triage:

```python
overview = ida.result("__result__ = ai.pwn_overview()", request_id="pwn.overview")
focus = ida.result(
    "__result__ = ai.focus(('main', 'vuln', 'backdoor'), disasm_limit=64)",
    request_id="pwn.focus",
)
```

Use `pwn_overview()` first for dangerous imports, shell strings, and suspicious
symbols. Then call `focus()` only on likely functions.

Large inventory:

```python
artifacts = ida.result(
    "__result__ = ai.export_inventory('inventory', string_limit=1024)",
    request_id="inventory.export",
)
```

Read returned artifact paths instead of asking for full lists.

Targeted RE:

```python
ctx = ida.result(
    "__result__ = ai.context_pack('main', disasm_limit=48, include_decompile=True)",
    request_id="re.main",
)
```

Mutation workflow: call proposal helpers such as `ai.propose_rename()` before
database-changing helpers, then call `ai.save_database()` only when persistence
is wanted.

## Helper Surface

Raw IDAPython remains unrestricted. `ai` helpers are ergonomic only.

Read helpers:
`functions`, `function`, `function_bounds`, `segments`, `entries`, `exports`,
`names`, `decompile`, `disasm`, `xrefs`, `xrefs_to`, `xrefs_from`, `callers`,
`callees`, `basic_blocks`, `cfg`, `strings`, `imports`, `bytes_at`,
`bytes_hex`, `item_size`, `comments`, `type_at`, `operand_value`, `demangle`,
`context_pack`.

Triage helpers:
`focus`, `inventory_summary`, `export_inventory`, `pwn_overview`.

Mutation helpers:
`rename`, `set_comment`, `set_repeatable_comment`, `set_nonrepeatable_comment`,
`apply_type`, `patch_bytes`, `patch_byte`, `save_database`, `propose_rename`,
`propose_comment`, `propose_type`, `propose_patch_bytes`,
`propose_save_database`.

Cache helpers:
`refresh_cache`, `cache_status`, `cached_functions`,
`cached_name_to_address`, `cached_address_to_function`, `cached_string_refs`,
`cached_import_refs`, `cached_call_edges`, `cached_decompile`, `export_cache`,
`save_cache`, `load_cache`.

Merge helpers:
`merge_changes`, `merge_change_sets`.

## Artifact Pattern

Use artifacts for large inventories:

```python
ida.result(
    "__result__ = ai.export_inventory('inventory', string_limit=1024)",
    request_id="inventory.export",
)
```

Read returned artifact paths instead of bloating JSONL responses.

## Verify Changes

```powershell
python -B -m unittest discover -s tests -v
python -B -m compileall -q src tests benches examples scripts
```

After smoke tests, remove project-local `runs/`, temporary smoke directories,
and `__pycache__`.
