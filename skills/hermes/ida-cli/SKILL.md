---
name: ida-cli
description: Use when you need to drive local IDA Pro or Hex-Rays for binary analysis — decompile, disassemble, inspect functions, query xrefs/strings/imports, triage Pwn/CTF binaries, or modify IDA databases (rename, comment, patch). Uses IDA-CLI's AI-only JSONL kernel with unrestricted IDAPython over stdin/stdout — no GUI, no MCP, no middleware.
version: 1.0.0
author: ze-mu-zhou/IDACLI
license: MIT
metadata:
  hermes:
    tags: [reverse-engineering, ida-pro, binary-analysis, hex-rays, idapython, ctf, malware-analysis]
    related_skills: [writing-plans]
---

# IDA-CLI — AI-Native IDA Pro / Hex-Rays JSONL Kernel

Drive IDA Pro from Hermes via the IDA-CLI JSONL kernel subprocess. One target argument, stdin JSONL requests, stdout JSONL responses, unrestricted Python execution with persistent globals and artifact-backed large outputs.

Supported: IDA Pro 9.0+ simple-open idalib workflows.

## When to Use

- Binary triage: identify dangerous imports, shell strings, suspicious symbols in one call
- Reverse engineering: decompile functions, trace xrefs, enumerate strings/imports
- CTF/Pwn: find backdoors, overflowable buffers, format string vulnerabilities
- Database mutations: rename symbols, add comments, patch bytes, save
- Large binary inventory: export structured data via artifacts, avoid protocol bloat

Don't use for: hex-dumping without analysis context (use `xxd`), non-IDA debugging (use GDB/pwndbg), or targets on remote machines without local IDA.

## Prerequisites

IDA Pro 9.0+ installed and idalib activated:

```bash
cd <IDA_ROOT>/idalib/python
pip install idapro
python py-activate-idalib.py
```

## Install Runtime

From the repository root, install the `ida-cli` package into the same Python that has `idapro`:

```bash
cd <IDACLI_REPO>
pip install -e .
```

In WSL, IDA-CLI auto-detects your Windows Python with idapro — no manual path configuration needed. Set `IDA_CLI_PYTHON` to override detection.

## Usage from Hermes

Use `terminal` to pipe JSONL requests to the kernel:

```bash
# Single request
echo '{"id":"probe","code":"__result__ = __backend__"}' | ida-ai path/to/target.i64
```

For multi-request sessions, use the `AgentSession` Python bridge (keeps one subprocess alive):

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start("target.i64", require_ida=True) as ida:
    backend = ida.probe_backend(require_ida=True)
    funcs = ida.result("__result__ = ai.functions()")
    decomp = ida.result("__result__ = ai.decompile('main')")
```

## Required First Probe

Always verify the IDA backend is available before analysis work:

```json
{"id":"probe","code":"__result__ = __backend__"}
```

Expected: `{"ok":true, "result":{"ida_available":true, "database_opened":true, "name":"idalib"}}`

## Common Workflows

### Pwn/CTF Triage

```python
# One-shot security overview
ida.result("__result__ = ai.pwn_overview()", request_id="pwn.overview")

# Focus on suspicious functions only
ida.result(
    "__result__ = ai.focus(('main', 'backdoor'), disasm_limit=64)",
    request_id="pwn.focus",
)
```

### Large Binary Inventory (use artifacts)

```python
ida.result(
    "__result__ = ai.export_inventory('inventory', string_limit=1024)",
    request_id="inventory.export",
)
# Read returned artifact file path — don't inline large results
```

### Targeted Reverse Engineering

```python
# Decompile + disasm + xrefs in one call
ctx = ida.result(
    "__result__ = ai.context_pack('target_func', disasm_limit=48, include_decompile=True)",
    request_id="re.target",
)
```

### Database Mutations (propose → apply → save)

```python
ida.result("__result__ = ai.propose_rename(0x401000, 'vuln_func')")
ida.result("__result__ = ai.rename(0x401000, 'vuln_func')")
ida.result("__result__ = ai.save_database()")
```

## JSONL Protocol

Every request is one strict JSON object with `code` (required) and optional `id`:

```json
{"id":"my_request","code":"__result__ = ai.decompile('main')"}
```

Response shape (success):

```json
{"ok":true,"result":<value of __result__>,"stdout":"","stderr":"","elapsed_ms":N,"id":"my_request"}
```

Response shape (error):

```json
{"ok":false,"error":{"type":"TypeError","message":"...","traceback":"..."},"stdout":"","stderr":"","elapsed_ms":N,"id":"my_request"}
```

The kernel resolves code through exec() in persistent globals — you can store state across requests within one session.

## Helper Surface

Raw IDAPython is unrestricted. `ai` helpers are ergonomic shortcuts:

**Read helpers:**
`functions`, `function`, `function_bounds`, `segments`, `entries`, `exports`,
`names`, `decompile`, `disasm`, `xrefs`, `xrefs_to`, `xrefs_from`, `callers`,
`callees`, `basic_blocks`, `cfg`, `strings`, `imports`, `bytes_at`,
`bytes_hex`, `item_size`, `comments`, `type_at`, `operand_value`, `demangle`,
`context_pack`

**Triage helpers:**
`focus`, `inventory_summary`, `export_inventory`, `pwn_overview`

**Mutation helpers:**
`rename`, `set_comment`, `set_repeatable_comment`, `set_nonrepeatable_comment`,
`apply_type`, `patch_bytes`, `patch_byte`, `save_database`, `propose_rename`,
`propose_comment`, `propose_type`, `propose_patch_bytes`, `propose_save_database`

**Cache helpers:**
`refresh_cache`, `cache_status`, `cached_functions`, `cached_name_to_address`,
`cached_address_to_function`, `cached_string_refs`, `cached_import_refs`,
`cached_call_edges`, `cached_decompile`, `export_cache`, `save_cache`, `load_cache`

**Merge helpers:**
`merge_changes`, `merge_change_sets`

All limit/string-count parameters consistently use `string_limit`.

## Parallel Analysis

Spawn isolated IDA kernels on database snapshots:

```python
from ida_cli.parallel_runner import ParallelRunner
# True process-level isolation, not unsafe thread concurrency
```

## Common Pitfalls

1. **Skipping `probe_backend`** — verify IDA is available before analysis requests, or Python-only mode errors will confuse you.

2. **Multiple kernels on the same `.i64`** — creates conflicting mutations. Use `parallel_runner` for safe multi-kernel analysis on database copies.

3. **One session per analysis pass** — keep one `AgentSession` alive for the whole pass. Don't restart the kernel per request; IDA auto-analysis and caches are expensive to rebuild.

4. **Mutations without proposals** — always use `ai.propose_*` to preview before committing with `ai.save_database()`.

5. **Large responses in JSONL** — use `export_inventory` with artifacts for full inventories. JSONL responses over ~100KB risk protocol timeouts.

6. **Forgetting `__result__`** — the kernel serializes what's in the `__result__` global. If your code doesn't set it, the response is empty.

7. **WSL: AgentSession handles paths automatically** — `AgentSession.start("/mnt/d/pwn/pwn")` auto-converts to `D:\pwn\pwn` and uses the correct Python. If you're piping raw JSONL to `ida-ai`, use `ida_cli.wsl.wsl_to_win()` or set `IDA_CLI_PYTHON`.

## Verification Checklist

- [ ] `idapro` is importable in the target Python: `python -c "import idapro"`
- [ ] `ida_cli` package installed: `python -c "import ida_cli"`
- [ ] Kernel starts and backend probe returns `ida_available: true`
- [ ] At least one decompile works: `ai.decompile('main')`
- [ ] Tests pass: `python -B -m unittest discover -s tests -v`
