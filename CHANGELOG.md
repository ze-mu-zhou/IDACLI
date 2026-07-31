# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Reasonix skill flavor (`skills/reasonix/ida-cli/`), wired into `install_skill.py` (`reasonix` / `all`), `AI_INSTALL.md`, READMEs, and skill-distribution tests.
- `--help` / `--version` CLI front door; `ida_cli.__version__` (kept in sync with `pyproject.toml` by test).
- GitHub Actions CI: unittest matrix on ubuntu-latest / windows-latest, Python 3.11 / 3.12.
- MIT `LICENSE` file and packaging metadata (license, authors, urls, classifiers).
- `MANIFEST.in` so sdists are self-contained: the test suite plus the `skills/`, `scripts/`, `docs/`, `benches/`, and `examples/` trees the tests and README links depend on.
- Daemon: protocol banner handshake for liveness probes, per-request socket timeouts, token/PID/port files written `O_EXCL` + `0600`, graceful SIGTERM shutdown, and `_MainThreadExecutor` so IDA API calls run on the thread that owns the database.
- Persistent-cache database fingerprinting (refuses foreign-DB cache without `force=`).
- Review backlog with self-install findings: `docs/REVIEW_BACKLOG.md`.

### Changed

- Agent skill support narrowed to Kimi Code + Codex; claude/hermes flavors removed.
- `_normalize_target_path` resolves non-`/mnt/` paths to absolute, so relative and absolute spellings of a target share one daemon identity.
- `patch_bytes` rolls back on mid-apply failure and always invalidates affected caches after writes.

### Fixed

- Protocol stdout protected against fd-level plugin noise (e.g. IDA plugin banners written directly to fd 1).
- WSL detection no longer misfires on a bare `WSLENV` (Windows Terminal); `wsl.exe` console output decoded safely (UTF-16/UTF-8).
- `SystemExit` in executed code returns a structured error envelope instead of killing the kernel; format errors keep their request id; non-UTF-8 stdin tolerated; stdout capture is thread-safe.
- Review findings across runtime, protocol, daemon, cache, mutations, conflicts, artifacts, and worker pool — see `docs/REVIEW_BACKLOG.md`.

## [0.1.0] - 2026-05-01

- Initial AI-only IDA CLI runtime: JSONL kernel over stdio, agent bridge, reusable daemon mode, WSL path support, parallel runner, artifact store, and agent skills.
