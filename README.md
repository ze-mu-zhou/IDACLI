# IDA-CLI

AI-only IDA Pro / Hex-Rays JSONL kernel with ready-to-install skills for Codex
and Claude Code.

## Install Runtime

```text
git clone <repo-url> IDA-CLI
cd IDA-CLI
python -m pip install -e .
```

`ida-ai target.i64` starts one unrestricted Python kernel. Requests are JSONL on
stdin, responses are JSONL on stdout, and large outputs should be written as
artifacts.

## Install Skills

Install both skills:

```text
python scripts/install_skill.py all --force
```

Install only one agent flavor:

```text
python scripts/install_skill.py codex --force
python scripts/install_skill.py claude --force
```

Defaults:

- Codex: `%CODEX_HOME%\skills\ida-cli` or `~/.codex/skills/ida-cli`
- Claude Code: `~/.claude/skills/ida-cli`

Claude Code also gets a project skill directly from this repository at
`.claude/skills/ida-cli/SKILL.md` when the repo is opened as a project.

## Agent Bridge

Agents can drive IDA from Python:

```python
from ida_cli.agent_bridge import AgentSession

with AgentSession.start(r"D:\samples\target.i64") as ida:
    backend = ida.result("__result__ = __backend__", request_id="probe.backend")
    functions = ida.result("__result__ = ai.functions()", request_id="inventory.functions")
```

## Verify

```text
python -B -m unittest discover -s tests -v
python -B -m compileall -q src tests benches examples scripts
```
