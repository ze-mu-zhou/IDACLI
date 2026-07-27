# AI Installation Guide

This guide is for AI agents that need to install and drive IDA-CLI from a local
workspace. Read this before trying to use the skill or the Python bridge.

## Scope

IDA-CLI is a local JSONL Python kernel around one IDA database when `idapro` is
available. It is not an MCP server. If the host only accepts MCP tools, use an
IDA MCP project instead of trying to wrap this protocol on the fly.

The supported IDA surface is `IDA Pro 9.0+` simple-open idalib workflows.
IDA 9.1/9.2 loader-argument extensions are not surfaced here; the kernel
intentionally accepts one target path only.

## 1. Install or activate `idapro` first

Follow the official idalib flow from `<IDA_ROOT>/idalib/python` before using
IDA-CLI for real analysis:

```text
python -m pip install idapro
python py-activate-idalib.py
```

IDA Pro 9.3 also ships prebuilt wheels in that directory, but the agent should
still treat `idapro` importability as the real readiness check.

IDA-CLI probes an already importable `idapro` first. If the official activation
step was skipped, the runtime next checks `IDADIR` and bounded Windows install
layouts. Full-drive discovery is disabled by default because it is slow; enable
it only as a last resort on Windows with `IDA_CLI_DEEP_IDA_DISCOVERY=1`.

### One-time IDA license acceptance

Hex-Rays requires each OS user that runs idalib to launch IDA once and accept
the license terms before batch mode is allowed. A valid `.hexlic` file and a
loadable `idalib.dll` do not replace this one-time user action.

Use the structured readiness check first:

```text
ida-ai doctor
```

If it reports `IdaLicenseNotAcceptedError`, the agent may run:

```text
ida-ai doctor --fix-license
```

That command launches the configured official IDA executable, waits for the
user to review the terms and close IDA, and then retries the isolated `idapro`
probe. The agent must not click acceptance controls for the user, write an
undocumented acceptance marker, or alter IDA licensing components.

## 2. Install the runtime wrapper

From the repository root:

```text
python -m pip install -e .
```

## 3. Install the skill files

### Install Codex skill directly from GitHub

Prefer Codex's built-in `$skill-installer` when no local clone is needed. Ask
Codex to install this exact GitHub path:

```text
Use $skill-installer to install:
https://github.com/ze-mu-zhou/IDACLI/tree/main/skills/codex/ida-cli
```

The equivalent skill-installer helper arguments are:

```text
install-skill-from-github.py --repo ze-mu-zhou/IDACLI --ref main --path skills/codex/ida-cli
```

The installer refuses to overwrite an existing skill. For a clean reinstall,
first verify and remove only the installed
`<CODEX_HOME>/skills/ida-cli` directory, then repeat the GitHub installation.
Do not remove the IDA-CLI development clone. The newly installed skill is
available to Codex on the next turn.

### Install from a local clone

Install all agent flavors:

```text
python scripts/install_skill.py all --force
```

Install only one flavor:

```text
python scripts/install_skill.py codex --force
python scripts/install_skill.py kimi --force
python scripts/install_skill.py claude --force
```

Default locations:

- Codex: `%CODEX_HOME%\skills\ida-cli` or `~/.codex/skills/ida-cli`
- Kimi Code: `%KIMI_CODE_HOME%\skills\ida-cli` or `~/.kimi-code/skills/ida-cli`
- Claude Code: `%CLAUDE_CONFIG_DIR%\skills\ida-cli` or `~/.claude/skills/ida-cli`

The `ida-cli` Python package provides `ida-ai` and `AgentSession`. The skill
markdown and agent descriptors still come from this repository or a copied
skill tree.

## 4. Verify the packaged surfaces

Run the fast repo checks:

```text
python -B -m unittest tests.test_runtime_integration tests.test_skill_distribution -v
python -B -m compileall -q src tests benches examples scripts
```

## 5. First probe from Python

Prefer one long-lived `AgentSession` for an analysis pass:

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start("path/to/target.i64", require_ida=True) as ida:
    backend = ida.probe_backend(require_ida=True)
    summary = ida.result(
        "__result__ = ai.inventory_summary()",
        request_id="inventory.summary",
    )
```

What must be true:

- `backend["ida_available"]` is `True`
- `summary["counts"]` exists
- large inventories should use `ai.export_inventory(...)`, not one huge JSONL
  response

## 6. First probe from the raw kernel

If the agent cannot import Python modules directly, it may drive the raw kernel:

```text
ida-ai path/to/target.i64
```

Then send strict JSONL requests such as:

```json
{"id":"probe.backend","code":"__result__ = __backend__"}
{"id":"inventory.summary","code":"__result__ = ai.inventory_summary()"}
```

Do not expect human-readable stdout. The protocol surface is JSONL only.

## 7. Working rules

- Keep one session alive while analyzing a target so caches and auto-analysis are
  reused.
- Probe `__backend__` first and require `ida_available`.
- Use artifacts for large outputs.
- Treat this runtime as unrestricted local Python inside IDA. Do not expose it
  to untrusted remote callers.
