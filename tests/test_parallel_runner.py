"""Tests for IDA-free local subprocess parallel runner primitives."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.parallel_runner import (  # noqa: E402
    JsonlWorkerProcess,
    LocalParallelRunner,
    WorkerProtocolError,
    build_worker_request,
    parse_worker_response,
    plan_database_snapshots,
    plan_worker_launch,
    plan_worker_launches,
    prepare_database_snapshots,
    run_fanout_plan,
    worker_response_to_result,
    worker_specs_from_snapshots,
)
from ida_cli.supervisor import make_fanout_plan  # noqa: E402
from ida_cli.worker_pool import WorkerSpec  # noqa: E402


FAKE_WORKER = textwrap.dedent(
    """
    import contextlib
    import io
    import json
    import sys
    import time
    database_path = sys.argv[-1]
    globals_dict = {"__database_path__": database_path}
    for line in sys.stdin:
        request = json.loads(line)
        bindings = request.get("bindings", {})
        previous = {}
        missing = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        started = time.perf_counter_ns()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                for name, value in bindings.items():
                    if name in globals_dict:
                        previous[name] = globals_dict[name]
                    else:
                        missing.append(name)
                    globals_dict[name] = value
                try:
                    exec(request["code"], globals_dict, globals_dict)
                finally:
                    for name, value in previous.items():
                        globals_dict[name] = value
                    for name in missing:
                        globals_dict.pop(name, None)
            response = {
                "elapsed_ms": max(0, (time.perf_counter_ns() - started) // 1_000_000),
                "ok": True,
                "result": globals_dict.get("__result__"),
                "stderr": stderr.getvalue(),
                "stdout": stdout.getvalue(),
            }
        except Exception as exc:
            response = {
                "elapsed_ms": max(0, (time.perf_counter_ns() - started) // 1_000_000),
                "error": {"message": str(exc), "traceback": "", "type": type(exc).__name__},
                "ok": False,
                "stderr": stderr.getvalue(),
                "stdout": stdout.getvalue(),
            }
        if "id" in request:
            response["id"] = request["id"]
        sys.stdout.write(json.dumps(response, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\\n")
        sys.stdout.flush()
    """
)


def _fake_base_command() -> tuple[str, ...]:
    return (sys.executable, "-u", "-c", FAKE_WORKER)


class ParallelRunnerTests(unittest.TestCase):
    def test_database_snapshot_planning_and_copying_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.i64"
            source.write_bytes(b"database bytes")

            plans = plan_database_snapshots(target_path=source, worker_count=2, snapshot_dir=root / "snapshots")
            manifest = prepare_database_snapshots(plans)
            specs = worker_specs_from_snapshots(plans)

            self.assertEqual([Path(plan.snapshot_path).name for plan in plans], ["sample.worker-000.i64", "sample.worker-001.i64"])
            self.assertEqual(manifest.snapshot_count, 2)
            self.assertEqual(manifest.byte_count, len(b"database bytes") * 2)
            self.assertEqual([spec.database_path for spec in specs], [plan.snapshot_path for plan in plans])
            self.assertEqual(Path(plans[0].snapshot_path).read_bytes(), b"database bytes")

    def test_worker_launch_plan_appends_database_path_and_merges_env(self) -> None:
        spec = WorkerSpec.create(
            index=0,
            target_path="target.i64",
            database_path="snapshot.i64",
            argv=("--flag",),
            env={"A": "1"},
        )

        launch = plan_worker_launch(spec, base_command=("python", "-m", "ida_cli"), cwd=ROOT, env={"B": "2"})

        self.assertEqual(launch.argv, ("python", "-m", "ida_cli", "--flag", "snapshot.i64"))
        self.assertEqual(dict(launch.env), {"A": "1", "B": "2"})
        self.assertEqual(launch.database_path, "snapshot.i64")
        json.dumps(launch.as_dict(), allow_nan=False, sort_keys=True)

    def test_jsonl_worker_process_round_trips_one_request(self) -> None:
        spec = WorkerSpec.create(index=0, target_path="target.i64", database_path="worker0.i64")
        launch = plan_worker_launch(spec, base_command=_fake_base_command(), cwd=ROOT)

        with JsonlWorkerProcess(launch) as worker:
            response = worker.request(
                {
                    "id": "request-1",
                    "code": "__result__ = {'database': __database_path__, 'value': 21 * 2}",
                },
                timeout_s=2.0,
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["id"], "request-1")
        self.assertEqual(response["result"], {"database": "worker0.i64", "value": 42})

    def test_local_parallel_runner_aggregates_successes(self) -> None:
        plan = make_fanout_plan(
            target_path="target.i64",
            items=[{"ea": 1}, {"ea": 2}, {"ea": 3}],
            worker_count=2,
            database_paths=("worker0.i64", "worker1.i64"),
        )
        launches = plan_worker_launches(plan.worker_specs, base_command=_fake_base_command(), cwd=ROOT)
        runner = LocalParallelRunner(launches, timeout_s=2.0)

        result = runner.run(
            plan,
            "__result__ = {'worker': __worker_id__, 'items': __shard_items__, 'database': __database_path__}",
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.success_count, 2)
        self.assertEqual(result.item_count, 3)
        payloads = [record.result["result"] for record in result.results]
        self.assertEqual(payloads[0]["items"], [{"ea": 1}, {"ea": 2}])
        self.assertEqual(payloads[1]["database"], "worker1.i64")

    def test_worker_error_response_becomes_error_record(self) -> None:
        plan = make_fanout_plan(target_path="target.i64", items=[1], worker_count=1)

        result = run_fanout_plan(plan, "raise ValueError('bad shard')", base_command=_fake_base_command(), cwd=ROOT)

        self.assertFalse(result.ok)
        self.assertEqual(result.error_count, 1)
        self.assertEqual(result.results[0].error.as_dict()["type"], "ValueError")

    def test_worker_crash_becomes_crash_record_with_stderr_tail(self) -> None:
        plan = make_fanout_plan(target_path="target.i64", items=[1], worker_count=1)
        command = (
            sys.executable,
            "-u",
            "-c",
            "import sys; sys.stderr.write('fatal tail'); sys.stderr.flush(); sys.exit(7)",
        )

        result = run_fanout_plan(plan, "__result__ = 1", base_command=command, cwd=ROOT, timeout_s=2.0)

        self.assertFalse(result.ok)
        self.assertEqual(result.crash_count, 1)
        crash = result.results[0].crash.as_dict()
        self.assertEqual(crash["returncode"], 7)
        self.assertIn("fatal tail", crash["stderr_tail"])

    def test_worker_timeout_becomes_crash_record(self) -> None:
        plan = make_fanout_plan(target_path="target.i64", items=[1], worker_count=1)
        command = (
            sys.executable,
            "-u",
            "-c",
            "import sys, time; sys.stdin.readline(); time.sleep(30)",
        )

        result = run_fanout_plan(plan, "__result__ = 1", base_command=command, cwd=ROOT, timeout_s=0.2)

        self.assertFalse(result.ok)
        self.assertEqual(result.crash_count, 1)
        crash = result.results[0].crash.as_dict()
        self.assertEqual(crash["returncode"], -1)
        self.assertIn("timed out", crash["message"])

    def test_protocol_response_validation_fails_fast(self) -> None:
        with self.assertRaises(WorkerProtocolError):
            parse_worker_response('{"ok":true}\n')

        plan = make_fanout_plan(target_path="target.i64", items=[1], worker_count=1)
        request = build_worker_request(shard=plan.shards[0], code="__result__ = 3")
        self.assertEqual(request["id"], "shard-000")
        self.assertEqual(request["code"], "__result__ = 3")
        self.assertEqual(request["bindings"]["__shard_items__"], [1])

    def test_worker_response_to_result_preserves_captured_streams(self) -> None:
        plan = make_fanout_plan(target_path="target.i64", items=[1], worker_count=1)
        response = {
            "elapsed_ms": 4,
            "id": "shard-000",
            "ok": True,
            "result": {"value": 9},
            "stderr": "err",
            "stdout": "out",
        }

        record = worker_response_to_result(spec=plan.worker_specs[0], shard=plan.shards[0], response=response, elapsed_ms=5)

        self.assertTrue(record.ok)
        self.assertEqual(record.result["result"], {"value": 9})
        self.assertEqual(record.result["stdout"], "out")
        self.assertEqual(record.result["stderr"], "err")
        self.assertEqual(record.result["worker_elapsed_ms"], 4)


if __name__ == "__main__":
    unittest.main()
