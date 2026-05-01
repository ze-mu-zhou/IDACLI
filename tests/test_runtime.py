"""Tests for the unrestricted Python runtime contract."""

from __future__ import annotations

import json
import math
import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli.runtime import PythonRuntime, prepare_result


class RuntimeTests(unittest.TestCase):
    """Exercise persistent execution behavior without requiring IDA."""

    def test_executes_code_and_preserves_globals(self) -> None:
        """Persistent globals let later requests reuse AI-created state."""
        runtime = PythonRuntime()

        first = runtime.execute("counter = 41\n__result__ = counter", request_id="r1")
        second = runtime.execute("__result__ = counter + 1", request_id="r2")

        self.assertEqual(first["id"], "r1")
        self.assertTrue(first["ok"])
        self.assertEqual(first["result"], 41)
        self.assertEqual(second["id"], "r2")
        self.assertTrue(second["ok"])
        self.assertEqual(second["result"], 42)

    def test_missing_result_returns_null_until_set(self) -> None:
        """An unset result variable serializes as JSON null."""
        runtime = PythonRuntime()

        response = runtime.execute("cached = 'kept'")

        self.assertTrue(response["ok"])
        self.assertIsNone(response["result"])
        self.assertEqual(runtime.globals["cached"], "kept")

    def test_result_variable_is_request_scoped(self) -> None:
        """A prior result must not leak into a later request that omits it."""
        runtime = PythonRuntime()

        runtime.execute("__result__ = 'old'")
        response = runtime.execute("still = 'state survives'")

        self.assertTrue(response["ok"])
        self.assertIsNone(response["result"])
        self.assertEqual(runtime.globals["still"], "state survives")

    def test_explicit_null_protocol_id_is_preserved(self) -> None:
        """ProtocolRequest carries an explicit JSON null ID through runtime output."""
        runtime = PythonRuntime()

        response = runtime.execute_request(type("Request", (), {"code": "__result__ = 1", "request_id": None, "has_id": True})())

        self.assertTrue(response["ok"])
        self.assertIn("id", response)
        self.assertIsNone(response["id"])

    def test_ai_helper_allows_session_state(self) -> None:
        """The convenience ai object remains writable by unrestricted Python."""
        runtime = PythonRuntime()

        response = runtime.execute("ai.note = 'live'\n__result__ = ai.note")

        self.assertTrue(response["ok"])
        self.assertEqual(response["result"], "live")

    def test_captures_stdout_and_stderr(self) -> None:
        """Executed Python output is returned in fields, not leaked to stdout."""
        runtime = PythonRuntime()

        response = runtime.execute(
            "import sys\nprint('visible stdout')\nprint('visible stderr', file=sys.stderr)\n__result__ = 'done'"
        )

        self.assertTrue(response["ok"])
        self.assertEqual(response["stdout"], "visible stdout\n")
        self.assertEqual(response["stderr"], "visible stderr\n")
        self.assertEqual(response["result"], "done")

    def test_exception_response_is_structured_and_keeps_captured_output(self) -> None:
        """Execution failures return typed error data with traceback evidence."""
        runtime = PythonRuntime()

        response = runtime.execute("print('before boom')\nmissing_name + 1", request_id="bad")

        self.assertFalse(response["ok"])
        self.assertEqual(response["id"], "bad")
        self.assertEqual(response["stdout"], "before boom\n")
        self.assertEqual(response["stderr"], "")
        self.assertEqual(response["error"]["type"], "NameError")
        self.assertIn("missing_name", response["error"]["message"])
        self.assertIn("<ida-cli-request>", response["error"]["traceback"])
        self.assertTrue(response["error"]["frames"])

    def test_system_exit_is_not_swallowed(self) -> None:
        """Explicit Python exits remain available to the future kernel loop."""
        runtime = PythonRuntime()

        with self.assertRaises(SystemExit):
            runtime.execute("raise SystemExit(3)")

    def test_execute_request_uses_protocol_shaped_mapping(self) -> None:
        """Request mappings pass through IDs while protocol.py is still empty."""
        runtime = PythonRuntime()

        response = runtime.execute_request({"id": "map-1", "code": "__result__ = 7"})

        self.assertTrue(response["ok"])
        self.assertEqual(response["id"], "map-1")
        self.assertEqual(response["result"], 7)

    def test_request_bindings_are_scoped_to_one_request(self) -> None:
        """Per-request globals must not leak once the request finishes."""
        runtime = PythonRuntime(initial_globals={"__worker_id__": "persistent"})

        first = runtime.execute_request(
            {
                "id": "bind-1",
                "code": "__result__ = (__worker_id__, tuple(__shard_items__))",
                "bindings": {"__worker_id__": "worker-007", "__shard_items__": [1, 2, 3]},
            }
        )
        second = runtime.execute("__result__ = globals().get('__shard_items__', 'missing'), __worker_id__")

        self.assertTrue(first["ok"])
        self.assertEqual(first["result"], ["worker-007", [1, 2, 3]])
        self.assertTrue(second["ok"])
        self.assertEqual(second["result"], ["missing", "persistent"])

    def test_bad_request_code_returns_structured_error(self) -> None:
        """Invalid request source fails the request instead of guessing behavior."""
        runtime = PythonRuntime()

        response = runtime.execute_request({"id": "bad-code"})

        self.assertFalse(response["ok"])
        self.assertEqual(response["id"], "bad-code")
        self.assertEqual(response["error"]["type"], "RuntimeRequestError")

    def test_bad_request_bindings_return_structured_error(self) -> None:
        """Malformed binding envelopes must fail the request instead of leaking state."""
        runtime = PythonRuntime()

        response = runtime.execute_request({"id": "bad-bindings", "code": "__result__ = 1", "bindings": []})

        self.assertFalse(response["ok"])
        self.assertEqual(response["id"], "bad-bindings")
        self.assertEqual(response["error"]["type"], "RuntimeRequestError")

    def test_prepare_result_is_strict_json_compatible(self) -> None:
        """Non-native Python values are tagged so the envelope can be JSONL encoded."""
        value = {
            "bytes": b"\x00A",
            "nan": math.nan,
            "set": {3, 1, 2},
            9: "non-string-key",
        }

        prepared = prepare_result(value)
        encoded = json.dumps(prepared, allow_nan=False, sort_keys=True)

        self.assertIn('"__type__"', encoded)
        self.assertEqual(prepared["__type__"], "dict")
        self.assertEqual(prepared["items"][0][0], "bytes")

    def test_prepare_result_marks_cycles(self) -> None:
        """Recursive containers become explicit cycle metadata."""
        value: list[object] = []
        value.append(value)

        prepared = prepare_result(value)

        self.assertEqual(prepared, [{"__type__": "cycle", "python_type": "builtins.list"}])
        json.dumps(prepared, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
