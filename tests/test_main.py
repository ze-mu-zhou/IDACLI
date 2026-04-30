"""Tests for the JSONL command entry point."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli.__main__ import main
from ida_cli.kernel import PythonOnlyBackend, create_session


def _responses(text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in text.splitlines() if line]


class MainTests(unittest.TestCase):
    """Verify stdout stays JSONL while the runtime executes multiple requests."""

    def test_cli_loop_executes_multiple_requests_and_preserves_state(self) -> None:
        stdin = io.StringIO(
            '{"id":null,"code":"value = 40 + 2\\n__result__ = value"}\n'
            '{"id":"next","code":"__result__ = value"}\n'
        )
        stdout = io.StringIO()

        with mock.patch(
            "ida_cli.__main__.create_session",
            lambda target: create_session(target, backend=PythonOnlyBackend()),
        ):
            exit_code = main(["sample.i64"], stdin=stdin, stdout=stdout)

        self.assertEqual(exit_code, 0)
        payloads = _responses(stdout.getvalue())
        self.assertEqual(payloads[0]["id"], None)
        self.assertEqual(payloads[0]["result"], 42)
        self.assertEqual(payloads[1]["id"], "next")
        self.assertEqual(payloads[1]["result"], 42)

    def test_bad_json_writes_structured_error_and_exits_nonzero(self) -> None:
        stdout = io.StringIO()

        with mock.patch(
            "ida_cli.__main__.create_session",
            lambda target: create_session(target, backend=PythonOnlyBackend()),
        ):
            exit_code = main(["sample.i64"], stdin=io.StringIO('{"code":'), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "JSONDecodeError")

    def test_missing_target_is_protocol_error(self) -> None:
        stdout = io.StringIO()

        exit_code = main([], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["error"]["type"], "CLIArgumentError")


if __name__ == "__main__":
    unittest.main()
