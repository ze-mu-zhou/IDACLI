<div align="center">

# IDA-CLI

**AI-only JSONL Kernel for IDA Pro / Hex-Rays**

Give your AI agent unrestricted, persistent, low-latency access to a real IDA database — no GUI, no MCP, no wrappers.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](#requirements)
[![IDA Pro 9.0+](https://img.shields.io/badge/IDA%20Pro-9.0%2B-4b0082)](#requirements)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#requirements)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

> [!IMPORTANT]
> This project is built for AI agents. We strongly recommend letting your agent (Kimi Code / Codex / Claude Code) handle the installation and setup instead of doing it manually.
> 👉 [AI Installation Guide](https://github.com/ze-mu-zhou/IDACLI/blob/main/docs/AI_INSTALL.md)

**[中文文档](https://github.com/ze-mu-zhou/IDACLI/blob/main/README.md)**

</div>

---

## Why IDA-CLI?

Existing IDA integrations expose a fixed set of tools through MCP or REST, forcing the AI to work within someone else's abstraction. IDA-CLI takes a different approach: it hands the agent a **raw Python kernel** connected to a live IDA database over stdin/stdout JSONL.

| | IDA-CLI | Typical IDA MCP |
|---|---|---|
| **Protocol** | Raw JSONL over stdin/stdout | MCP transport with tool schemas |
| **Execution model** | Unrestricted IDAPython — run anything | Pre-declared tool set only |
| **State** | Persistent session with caches | Stateless per-call |
| **Latency** | Direct subprocess, zero network | HTTP/WebSocket overhead |
| **AI control** | Full — agent writes arbitrary Python | Partial — limited to declared tools |
| **Dependencies** | 0 | Varies |

## Key Features

### Unrestricted Python Kernel
The agent sends arbitrary IDAPython code and gets structured JSONL responses. No predefined tool boundaries — if IDA can do it, the agent can do it.

### AI Helper Layer (`ai.*`)
40+ high-level helpers purpose-built for AI workflows, all returning clean JSON:

```python
ai.decompile("main")          # Hex-Rays pseudocode
ai.functions()                 # All function records
ai.xrefs_to("printf")         # Cross-references
ai.cfg("vulnerable_func")     # Control flow graph
ai.pwn_overview()              # CTF/pwn triage in one call
ai.inventory_summary()         # Quick binary overview
ai.rename(0x401000, "win")     # Database mutations
ai.focus(["main", "vuln"])     # Multi-target evidence bundle
```

### Persistent Cache & Artifacts
- Built-in index cache (`IDACache`) avoids redundant IDA queries across a session
- Large results write to artifact files instead of bloating protocol responses
- Cache survives across requests — `save_cache()` / `load_cache()` for cross-session reuse

### Parallel Analysis
Run multiple isolated IDA kernels on database copies for parallel analysis. True process-level isolation, not unsafe threading inside one IDA instance.

### Database Mutations
First-class support for `rename`, `set_comment`, `apply_type`, `patch_bytes`, and `save_database` — with propose/apply separation and deterministic conflict merging for multi-branch workflows.

### Agent Bridge
One-liner Python integration for any agent framework:

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start("target.i64", require_ida=True) as ida:
    overview = ida.result("__result__ = ai.pwn_overview()")
    pseudocode = ida.result("__result__ = ai.decompile('main')")
```

### Multi-Agent Skill Distribution
Ships ready-to-install skills for **Kimi Code**, **Codex**, and **Claude Code** — one `install_skill.py` command and the agent knows how to drive IDA.

## Quick Start

### 1. Prerequisites

```bash
# Activate idalib (from your IDA Pro installation)
python -m pip install idapro
python py-activate-idalib.py
```

Hex-Rays requires the current OS user to accept the IDA license terms once
before the first headless/idalib run. IDA-CLI reports that state explicitly
and never accepts the terms silently on the user's behalf:

```bash
# Read-only: report the real IDA path, version, license file, and acceptance state
ida-ai doctor

# Launch official IDA once, then retry idapro after the user closes it
ida-ai doctor --fix-license
```

`--fix-license` only launches the detected official IDA executable. It does
not patch DLLs, copy registry acceptance markers, or simulate license-button clicks.

### 2. Install

```bash
python -m pip install -e .
```

### 3. Install Agent Skills

Codex can install directly from GitHub without cloning the repository first:

```text
Use $skill-installer to install:
https://github.com/ze-mu-zhou/IDACLI/tree/main/skills/codex/ida-cli
```

Use the commands below when installing from an existing local clone:

```bash
# All flavors
python scripts/install_skill.py all --force

# Or pick one
python scripts/install_skill.py kimi --force
python scripts/install_skill.py codex --force
python scripts/install_skill.py claude --force
```

### 4. Verify

```bash
python -B -m unittest discover -s tests -v
python -B -m compileall -q src tests benches examples scripts
```

### 5. Run

```bash
# Start the kernel
ida-ai path/to/target.i64

# Send JSONL requests via stdin
{"id":"probe","code":"__result__ = __backend__"}
{"id":"funcs","code":"__result__ = ai.inventory_summary()"}
```

## Daemon Mode (Persistent Kernel Across Sessions)

By default each `ida-ai <target>` launches a fresh kernel. Daemon mode keeps one IDA kernel alive across sessions: clients connect and disconnect over TCP while the database, globals, and caches are reused — no repeated IDA auto-analysis or cache rebuilds per session.

```bash
# Start (or reuse) the daemon for a target
ida-ai --daemon path/to/target.i64

# Stop the daemon for a target
ida-ai --shutdown path/to/target.i64
```

From Python, `AgentSession` handles it:

```python
from ida_cli.agent_bridge import AgentSession

# Spawn the daemon if needed, otherwise reuse the running one
with AgentSession.start("target.i64", daemon=True, require_ida=True) as ida:
    ...

# Attach to an already-running daemon
with AgentSession.connect("target.i64") as ida:
    ...
```

Security model:

- Binds `127.0.0.1` (loopback) only by default. Setting `IDA_CLI_DAEMON_HOST=0.0.0.0` opts into all interfaces (needed for some WSL↔Windows setups) and prints a startup warning.
- Each daemon generates a random auth token at startup, written next to the pid/port files in the daemon directory (`~/.ida-cli/daemons/`, or `/tmp/.ida-cli/daemons` under WSL; override with `IDA_CLI_DAEMON_DIR`) with owner-only permissions.
- Clients must authenticate with this token before any request is served; `AgentSession` / `DaemonClient` do this automatically.

## Architecture

```
┌──────────────┐     stdin (JSONL)      ┌──────────────────┐
│   AI Agent   │ ──────────────────────▶ │                  │
│              │                         │   ida-ai kernel  │
│  Kimi Code   │ ◀────────────────────── │                  │
│  Codex       │     stdout (JSONL)      │  ┌────────────┐  │
│  Claude Code │                         │  │  IDAPython  │  │
└──────────────┘                         │  │  + idalib   │  │
                                         │  └────────────┘  │
       ┌─────────────────────────────────┤                  │
       │          AgentSession           │  ┌────────────┐  │
       │  (Python bridge alternative)    │  │  ai.*       │  │
       └─────────────────────────────────┤  │  helpers    │  │
                                         │  └────────────┘  │
                                         │                  │
                                         │  ┌────────────┐  │
                                         │  │  IDACache   │  │
                                         │  │  Artifacts  │  │
                                         │  │  Mutations  │  │
                                         │  └────────────┘  │
                                         └──────────────────┘
```

## IDA-CLI vs IDA MCP

IDA-CLI is **not** an MCP server. Choose based on your agent's capabilities:

| Choose IDA-CLI when... | Choose IDA MCP when... |
|---|---|
| Agent can run local subprocesses | Agent only speaks MCP |
| You need persistent state & caches | Stateless tool calls are fine |
| You want unrestricted IDAPython | Pre-declared tool schemas are preferred |
| You need `AgentSession` or raw kernel | You need MCP transport compatibility |

## Requirements

| Component | Version |
|---|---|
| Python | >= 3.11 |
| IDA Pro | >= 9.0 (idalib workflow) |
| Runtime dependencies | **None** |

## Project Structure

```
src/ida_cli/
├── __init__.py          # Package marker
├── __main__.py          # Entry point (ida-ai CLI)
├── kernel.py            # JSONL kernel loop
├── runtime.py           # Python execution runtime
├── protocol.py          # JSONL encode/decode
├── ai_helpers.py        # 40+ AI convenience helpers
├── agent_bridge.py      # AgentSession for external agents
├── daemon.py            # Persistent cross-session kernel daemon (TCP)
├── cache.py             # Persistent index cache
├── mutations.py         # Database mutation helpers
├── conflicts.py         # Deterministic conflict merging
├── artifacts.py         # Large-result file writer
├── parallel_runner.py   # Multi-kernel parallel execution
├── supervisor.py        # Work fanout planning
├── worker_pool.py       # Isolated worker management
└── wsl.py               # WSL path conversion and Python detection
```

## Documentation

| Document | Description |
|---|---|
| [AI Install Guide](https://github.com/ze-mu-zhou/IDACLI/blob/main/docs/AI_INSTALL.md) | Step-by-step setup for AI agents |

## License

MIT
