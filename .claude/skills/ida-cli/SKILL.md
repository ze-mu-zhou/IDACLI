---
name: ida-cli
description: Drive local IDA Pro or Hex-Rays through the IDA-CLI AI-only JSONL kernel from Claude Code. Use when Claude Code needs IDAPython/idalib analysis from a CLI subprocess, artifact-backed reverse-engineering output, AI helper APIs, persistent cache reuse, mutation conflict merging, or binary inspection without opening IDA GUI panels.
allowed-tools:
  - Bash(python *)
  - Bash(python3 *)
  - Bash(py *)
  - Bash(ida-ai *)
---

# IDA-CLI

Use this skill from a cloned `IDA-CLI` repository or from an environment where
the `ida-cli` Python package is installed. The runtime is AI-only: one target
argument, stdin JSONL requests, stdout JSONL responses, unrestricted Python
execution, persistent globals, and artifact-backed large outputs.

## Install Runtime

From the repository root:

```bash
python -m pip install -e .
```

The runtime auto-discovers `IDADIR` and the common Windows install
`D:\IDA\idalib\python`.

## Use From Claude Code

Prefer a short Python driver that keeps one subprocess alive:

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start(r"D:\samples\target.i64", require_ida=True) as ida:
    backend = ida.backend
    funcs = ida.result("__result__ = ai.functions()", request_id="inventory.functions")
```

Keep one `AgentSession` alive for an analysis pass so IDA auto-analysis,
globals, imports, and caches are reused.
`AgentSession` validates response IDs, rejects non-strict JSON responses, and
times out hung requests by default; pass `timeout_s=` per request for known slow
decompiler work.

## Required First Probe

For IDA work, probe `__backend__` first and require `ida_available`.
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
`apply_type`, `patch_bytes`, `patch_byte`, `save_database`.

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

```bash
python -B -m unittest discover -s tests -v
python -B -m compileall -q src tests benches examples scripts
```

After smoke tests, remove project-local `runs/`, temporary smoke directories,
and `__pycache__`.
