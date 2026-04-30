# Project Rules

This project is built for AI agents, not human CLI users.

## Primary Objective

Expose IDA as a pure CLI, unrestricted, high-performance Python kernel for AI.
Every design choice must reduce latency, reduce protocol noise, or improve AI
control over IDA state.

## Interface Rules

- stdout must contain JSONL protocol responses only.
- stderr must not be used for routine logs.
- Human-readable formatting must not be part of the core protocol.
- Requests execute unrestricted Python unless a later explicit project decision
  changes that goal.
- The runtime must fail fast on protocol or execution errors.

## Implementation Bias

- Prefer simple explicit modules over framework abstractions.
- Prefer persistent state and caches when they reduce repeated IDA work.
- Prefer artifact files for large results.
- Prefer deterministic JSON-compatible data in protocol responses.
- Do not introduce third-party runtime dependencies without a measured reason.

## Parallelism Rule

High parallelism must come from multiple isolated IDA kernels and database
copies or snapshots. Do not pretend that arbitrary IDA API access is safely
parallel inside one mutable database process.

## Skill Rule

When changing behavior, update the installed Codex skill at
`C:\Users\Administrator\.codex\skills\ida-cli\SKILL.md` in the same patch so
the AI-facing contract remains current. Do not recreate project documentation
unless the user explicitly asks for it.
