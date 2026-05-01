<div align="center">

# IDA-CLI

**面向 AI 的 IDA Pro / Hex-Rays JSONL 内核**

让你的 AI Agent 以无限制、持久化、低延迟的方式直接操控真实 IDA 数据库 — 无需 GUI，无需 MCP，无需中间层。

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](#环境要求)
[![IDA Pro 9.0+](https://img.shields.io/badge/IDA%20Pro-9.0%2B-4b0082)](#环境要求)
[![零依赖](https://img.shields.io/badge/运行时依赖-0-brightgreen)](#环境要求)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

> [!IMPORTANT]
> 本项目专为 AI Agent 设计。强烈建议让你的 Agent（Claude Code / Codex）自行完成安装和配置，而非手动操作。
> 👉 [AI 安装指南](docs/AI_INSTALL.md)

**[English](README_EN.md)**

</div>

---

## 为什么选择 IDA-CLI？

现有的 IDA 集成方案通过 MCP 或 REST 暴露一组固定的工具，AI 只能在别人定义好的抽象边界内工作。IDA-CLI 采用完全不同的思路：直接把一个**原始 Python 内核**交给 Agent，通过 stdin/stdout JSONL 协议连接到活跃的 IDA 数据库。

| | IDA-CLI | 典型 IDA MCP |
|---|---|---|
| **协议** | stdin/stdout 原始 JSONL | MCP transport + tool schema |
| **执行模型** | 无限制 IDAPython — 想跑什么跑什么 | 只能调用预声明的 tool |
| **状态** | 持久会话 + 内置缓存 | 每次调用无状态 |
| **延迟** | 直接子进程，零网络开销 | HTTP/WebSocket 开销 |
| **AI 控制力** | 完全控制 — Agent 写任意 Python | 受限 — 只能用声明好的 tool |
| **运行时依赖** | **0** | 不等 |

## 核心特性

### 无限制 Python 内核
Agent 发送任意 IDAPython 代码，获得结构化 JSONL 响应。没有预定义的工具边界 — IDA 能做的，Agent 都能做。

### AI 辅助层 (`ai.*`)
40+ 个专为 AI 工作流设计的高层辅助函数，全部返回干净的 JSON：

```python
ai.decompile("main")          # Hex-Rays 伪代码
ai.functions()                 # 所有函数记录
ai.xrefs_to("printf")         # 交叉引用
ai.cfg("vulnerable_func")     # 控制流图
ai.pwn_overview()              # CTF/Pwn 一键分诊
ai.inventory_summary()         # 二进制快速概览
ai.rename(0x401000, "win")     # 数据库变更
ai.focus(["main", "vuln"])     # 多目标证据包
```

### 持久缓存与 Artifact
- 内置索引缓存（`IDACache`），同一会话内避免重复 IDA 查询
- 大结果自动写入 artifact 文件，不会撑爆协议响应
- 缓存跨请求存活 — `save_cache()` / `load_cache()` 支持跨会话复用

### 并行分析
在数据库副本上启动多个隔离的 IDA 内核进行并行分析。真正的进程级隔离，而非在单个 IDA 实例内做不安全的线程并发。

### 数据库变更
一等公民支持 `rename`、`set_comment`、`apply_type`、`patch_bytes`、`save_database` — 提供 propose/apply 分离机制和确定性冲突合并，适配多分支工作流。

### Agent Bridge
一行代码接入任意 Agent 框架：

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start("target.i64", require_ida=True) as ida:
    overview = ida.result("__result__ = ai.pwn_overview()")
    pseudocode = ida.result("__result__ = ai.decompile('main')")
```

### 多 Agent Skill 分发
内置 **Claude Code**、**Codex**、**OpenAI Agents** 的 skill 文件 — 一条 `install_skill.py` 命令，Agent 即刻学会驱动 IDA。

## 快速开始

### 1. 前置条件

```bash
# 激活 idalib（在你的 IDA Pro 安装目录下）
python -m pip install idapro
python py-activate-idalib.py
```

### 2. 安装

```bash
python -m pip install -e .
```

### 3. 安装 Agent Skill

```bash
# 安装所有 Agent 风格
python scripts/install_skill.py all --force

# 或者只装一个
python scripts/install_skill.py claude --force
python scripts/install_skill.py codex --force
```

### 4. 验证

```bash
python -B -m unittest discover -s tests -v
python -B -m compileall -q src tests benches examples scripts
```

### 5. 运行

```bash
# 启动内核
ida-ai path/to/target.i64

# 通过 stdin 发送 JSONL 请求
{"id":"probe","code":"__result__ = __backend__"}
{"id":"funcs","code":"__result__ = ai.inventory_summary()"}
```

## 架构

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
       │    (Python Bridge 替代方案)     │  │  ai.*       │  │
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

IDA-CLI **不是** MCP server。根据你的 Agent 能力选择：

| 选 IDA-CLI 当... | 选 IDA MCP 当... |
|---|---|
| Agent 能跑本地子进程 | Agent 只会说 MCP 协议 |
| 需要持久状态和缓存 | 无状态调用就够了 |
| 需要无限制 IDAPython | 更倾向预声明的 tool schema |
| 需要 `AgentSession` 或原始内核 | 需要 MCP transport 兼容性 |

## 环境要求

| 组件 | 版本 |
|---|---|
| Python | >= 3.11 |
| IDA Pro | >= 9.0（idalib 工作流） |
| 运行时依赖 | **无** |

## 项目结构

```
src/ida_cli/
├── __main__.py          # 入口（ida-ai CLI）
├── kernel.py            # JSONL 内核循环
├── runtime.py           # Python 执行运行时
├── protocol.py          # JSONL 编解码
├── ai_helpers.py        # 40+ AI 辅助函数
├── agent_bridge.py      # AgentSession 外部 Agent 桥接
├── cache.py             # 持久索引缓存
├── mutations.py         # 数据库变更辅助
├── conflicts.py         # 确定性冲突合并
├── artifacts.py         # 大结果文件写入
├── parallel_runner.py   # 多内核并行执行
├── supervisor.py        # 工作扇出规划
└── worker_pool.py       # 隔离 Worker 管理
```

## 文档

| 文档 | 说明 |
|---|---|
| [AI 安装指南](docs/AI_INSTALL.md) | 面向 AI Agent 的安装流程 |
| [AGENTS.md](AGENTS.md) | 项目规则与设计原则 |

## License

MIT
