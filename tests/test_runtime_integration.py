"""IDA-free integration contracts for late runtime surfaces."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.artifacts import ArtifactStore  # noqa: E402
from ida_cli.runtime import PythonRuntime  # noqa: E402
from ida_cli.supervisor import SHARD_STABLE_HASH, make_fanout_plan  # noqa: E402
from ida_cli.worker_pool import LocalWorkerPool  # noqa: E402


class RecordingMutationHelper:
    """Runtime-injected mutation helper used to prove the mutation contract."""

    def __init__(self, store: ArtifactStore) -> None:
        self._store = store
        self._changes: list[dict[str, Any]] = []

    def rename(self, ea: int, new_name: str) -> dict[str, Any]:
        change = {"operation": "rename", "ea": int(ea), "new_name": str(new_name), "ok": True}
        self._changes.append(change)
        return change

    def set_comment(self, ea: int, text: str, *, repeatable: bool) -> dict[str, Any]:
        change = {
            "operation": "comment",
            "ea": int(ea),
            "text": str(text),
            "repeatable": bool(repeatable),
            "ok": True,
        }
        self._changes.append(change)
        return change

    def apply_type(self, ea: int, declaration: str) -> dict[str, Any]:
        change = {"operation": "type", "ea": int(ea), "declaration": str(declaration), "ok": True}
        self._changes.append(change)
        return change

    def patch_bytes(self, ea: int, data_hex: str) -> dict[str, Any]:
        change = {"operation": "patch_bytes", "ea": int(ea), "data_hex": str(data_hex), "ok": True}
        self._changes.append(change)
        return change

    def save_database(self) -> dict[str, Any]:
        change = {"operation": "save_database", "ok": True}
        self._changes.append(change)
        return change

    def export_changes(self, name: str) -> dict[str, Any]:
        return self._store.write_jsonl(name, self._changes)


class ExportableCacheHelper:
    """Runtime-injected cache helper used to prove the cache artifact contract."""

    def __init__(self, store: ArtifactStore) -> None:
        self._store = store
        self._cache = {
            "functions": [{"ea": 0x401000, "name": "start", "end_ea": 0x401020}],
            "names": {"start": 0x401000},
            "address_to_function": {"0x401010": 0x401000},
            "strings": [{"ea": 0x402000, "value": "hello"}],
            "imports": [{"module": "msvcrt", "name": "puts", "ea": 0x403000}],
            "call_edges": [{"source": 0x401000, "target": 0x403000}],
            "decompile": {"0x401000": "int start(void) { return 0; }"},
        }

    def refresh_cache(self, sections: tuple[str, ...]) -> dict[str, Any]:
        return {"refreshed": list(sections), "stale": []}

    def export_cache(self, name: str) -> dict[str, Any]:
        return self._store.write_json(name, self._cache)


class RuntimeIntegrationTests(unittest.TestCase):
    """Exercise late runtime behavior through public, IDA-free surfaces."""

    def test_mutation_helper_can_be_injected_and_export_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="mutation")
            runtime = PythonRuntime(ai=RecordingMutationHelper(store))

            response = runtime.execute(
                "\n".join(
                    (
                        "rename = ai.rename(0x401000, 'init_config')",
                        "rep = ai.set_comment(0x401000, 'reviewed', repeatable=True)",
                        "nonrep = ai.set_comment(0x401004, 'fallthrough', repeatable=False)",
                        "typed = ai.apply_type(0x401000, 'int __cdecl init_config(void)')",
                        "patch = ai.patch_bytes(0x401010, '9090')",
                        "save = ai.save_database()",
                        "artifact = ai.export_changes('changes/applied.jsonl')",
                        "__result__ = {",
                        "    'operations': [rename, rep, nonrep, typed, patch, save],",
                        "    'artifact': artifact,",
                        "}",
                    )
                )
            )

            artifact = store.artifact_dir / "changes" / "applied.jsonl"
            rows = [json.loads(line) for line in artifact.read_text(encoding="utf-8").splitlines()]

        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["operations"][0]["new_name"], "init_config")
        self.assertEqual(response["result"]["operations"][1]["repeatable"], True)
        self.assertEqual(response["result"]["operations"][2]["repeatable"], False)
        self.assertEqual(response["result"]["operations"][4]["data_hex"], "9090")
        self.assertEqual(response["result"]["artifact"]["count"], 6)
        self.assertEqual([row["operation"] for row in rows], ["rename", "comment", "comment", "type", "patch_bytes", "save_database"])

    def test_cache_export_returns_artifact_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="cache")
            runtime = PythonRuntime(ai=ExportableCacheHelper(store), run_dir=str(store.run_dir))

            response = runtime.execute(
                "\n".join(
                    (
                        "refresh = ai.refresh_cache(('functions', 'imports', 'call_edges'))",
                        "export = ai.export_cache('cache/indexes.json')",
                        "__result__ = {'refresh': refresh, 'export': export}",
                    )
                )
            )

            exported = json.loads((store.artifact_dir / "cache" / "indexes.json").read_text(encoding="utf-8"))

        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["refresh"]["stale"], [])
        self.assertEqual(response["result"]["export"]["artifact"], "runs/cache/artifacts/cache/indexes.json")
        self.assertEqual(exported["names"]["start"], 0x401000)
        self.assertEqual(exported["call_edges"][0]["target"], 0x403000)

    def test_parallel_runner_plan_is_json_compatible_and_isolated(self) -> None:
        database_paths = ("target.worker0.i64", "target.worker1.i64", "target.worker2.i64")
        items = [{"ea": 0x401000}, {"ea": 0x402000}, {"ea": 0x403000}, {"ea": 0x404000}]
        plan = make_fanout_plan(
            target_path="target.i64",
            items=items,
            worker_count=3,
            database_paths=database_paths,
            strategy=SHARD_STABLE_HASH,
            argv=("--jsonl",),
            env={"IDA_CLI_MODE": "worker"},
        )

        payload = plan.as_dict()
        pool = LocalWorkerPool(plan.worker_specs)
        result = pool.fanout(
            plan.shards,
            lambda spec, shard: {
                "worker_id": spec.worker_id,
                "database_path": spec.database_path,
                "item_count": len(shard),
            },
        )

        json.dumps(payload, allow_nan=False, sort_keys=True)
        json.dumps(result.as_dict(), allow_nan=False, sort_keys=True)
        self.assertEqual(payload["worker_count"], 3)
        self.assertEqual({worker["database_path"] for worker in payload["workers"]}, set(database_paths))
        self.assertTrue(result.ok, result.as_dict())
        self.assertEqual(result.item_count, len(items))

    def test_protocol_benchmark_script_exists_and_emits_json(self) -> None:
        script = ROOT / "benches" / "bench_protocol_runtime.py"
        self.assertTrue(script.is_file(), "benches/bench_protocol_runtime.py must exist")

        completed = subprocess.run(
            [sys.executable, "-B", str(script)],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        payload = json.loads(lines[0])

        self.assertEqual(completed.stderr, "")
        self.assertEqual(len(lines), 1)
        self.assertGreater(payload["iterations"], 0)
        self.assertIn("runtime_request_ns", payload)
        self.assertIn("protocol_roundtrip_ns", payload)
        self.assertIn("artifact_jsonl", payload)
        self.assertIn("metadata", payload["artifact_jsonl"])
        self.assertIn("sha256", payload["artifact_jsonl"]["metadata"])

    def test_packaging_skill_and_ai_callable_examples_are_present(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        scripts = pyproject["project"]["scripts"]
        codex_skill = ROOT / "skills" / "codex" / "ida-cli" / "SKILL.md"
        claude_skill = ROOT / "skills" / "claude" / "ida-cli" / "SKILL.md"
        project_claude_skill = ROOT / ".claude" / "skills" / "ida-cli" / "SKILL.md"
        examples_dir = ROOT / "examples"
        request_examples = sorted(examples_dir.glob("*.jsonl"))

        self.assertEqual(scripts.get("ida-ai"), "ida_cli.__main__:main")
        self.assertEqual(pyproject["project"].get("readme"), "README.md")
        with self.subTest("repo skills"):
            for skill in (codex_skill, claude_skill, project_claude_skill):
                self.assertTrue(skill.is_file(), f"missing distributed skill: {skill}")
            text = "\n".join(skill.read_text(encoding="utf-8").lower() for skill in (codex_skill, claude_skill))
            for token in (
                "agent_bridge",
                "jsonl",
                "idalib",
                "artifact",
                "cache",
                "merge",
                "common workflows",
                "pwn_overview",
                "focus",
                "export_inventory",
            ):
                self.assertIn(token, text)
        with self.subTest("jsonl request examples"):
            self.assertTrue(request_examples, "examples/*.jsonl must contain AI-callable JSONL requests")
        for example in request_examples:
            with self.subTest(example=example.name):
                for line in example.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        request = json.loads(line)
                        self.assertIn("code", request)


if __name__ == "__main__":
    unittest.main()
