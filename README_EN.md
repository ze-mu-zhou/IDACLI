<div align="center">

# IDA-CLI

**AI-only JSONL Kernel for IDA Pro / Hex-Rays**

Give your AI agent unrestricted, persistent, low-latency access to a real IDA database — no GUI, no MCP, no wrappers.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](#requirements)
[![IDA Pro 9.0+](https://img.shields.io/badge/IDA%20Pro-9.0%2B-4b0082)](#requirements)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#requirements)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

> [!IMPORTANT]
> This project is built for AI agents. We strongly recommend letting your agent (Claude Code / Codex) handle the installation and setup instead of doing it manually.
> 👉 [AI Installation Guide](docs/AI_INSTALL.md)

**[中文文档](README.md)**

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
Ships ready-to-install skills for **Claude Code**, **Codex**, and **OpenAI Agents** — one `install_skill.py` command and the agent knows how to drive IDA.

## Quick Start

### 1. Prerequisites

```bash
# Activate idalib (from your IDA Pro installation)
python -m pip install idapro
python py-activate-idalib.py
```

### 2. Install

```bash
python -m pip install -e .
```

### 3. Install Agent Skills

```bash
# All flavors
python scripts/install_skill.py all --force

# Or pick one
python scripts/install_skill.py claude --force
python scripts/install_skill.py codex --force
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

## Architecture

```
┌──────────────┐     stdin (JSONL)      ┌──────────────────┐
│   AI Agent   │ ──────────────────────▶ │                  │
│              │                         │   ida-ai kernel  │
│  Claude Code │ ◀────────────────────── │                  │
│  Codex       │     stdout (JSONL)      │  ┌────────────┐  │
│  OpenAI      │                         │  │  IDAPython  │  │
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
├── __main__.py          # Entry point (ida-ai CLI)
├── kernel.py            # JSONL kernel loop
├── runtime.py           # Python execution runtime
├── protocol.py          # JSONL encode/decode
├── ai_helpers.py        # 40+ AI convenience helpers
├── agent_bridge.py      # AgentSession for external agents
├── cache.py             # Persistent index cache
├── mutations.py         # Database mutation helpers
├── conflicts.py         # Deterministic conflict merging
├── artifacts.py         # Large-result file writer
├── parallel_runner.py   # Multi-kernel parallel execution
├── supervisor.py        # Work fanout planning
└── worker_pool.py       # Isolated worker management
```

## Documentation

| Document | Description |
|---|---|
| [AI Install Guide](docs/AI_INSTALL.md) | Step-by-step setup for AI agents |
| [AGENTS.md](AGENTS.md) | Project rules and design principles |

## License

MIT
