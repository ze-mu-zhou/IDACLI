"""Tests for external-agent subprocess integration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.agent_bridge import AgentBridgeError, AgentSession


def _python_only_command() -> tuple[str, ...]:
    """Return a subprocess command that forces the Python backend for tests."""

    code = (
        "import sys;"
        f"sys.path.insert(0, {str(SRC)!r});"
        "import ida_cli.__main__ as main_mod;"
        "from ida_cli.kernel import PythonOnlyBackend, create_session;"
        "main_mod.create_session = lambda target: create_session(target, backend=PythonOnlyBackend());"
        "raise SystemExit(main_mod.main())"
    )
    return (sys.executable, "-B", "-c", code)


class AgentBridgeTests(unittest.TestCase):
    """Exercise the bridge exactly as an external coding agent would use it."""

    def test_agent_session_preserves_state_and_raw_protocol_response(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command()) as session:
            first = session.execute("value = 41\n__result__ = value + 1", request_id="first")
            second = session.result("__result__ = value", request_id=None)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first["id"], "first")
        self.assertEqual(first["result"], 42)
        self.assertEqual(second, 41)

    def test_agent_session_result_raises_with_structured_response(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command()) as session:
            with self.assertRaisesRegex(AgentBridgeError, "ValueError: boom") as captured:
                session.result("raise ValueError('boom')", request_id="err")

        self.assertIsNotNone(captured.exception.response)
        self.assertEqual(captured.exception.response["id"], "err")
        self.assertFalse(captured.exception.response["ok"])

    def test_probe_backend_caches_metadata_and_can_require_ida(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command(), probe_backend=True) as session:
            backend = session.backend

        self.assertIsNotNone(backend)
        self.assertEqual(backend["name"], "python")
        with self.assertRaisesRegex(AgentBridgeError, "IDA backend required"):
            AgentSession.start("sample.i64", command=_python_only_command(), require_ida=True)

    def test_agent_session_rejects_mismatched_response_id(self) -> None:
        command = _one_response_command('{"id":"wrong","ok":true,"result":1}')
        with AgentSession.start("sample.i64", command=command) as session:
            with self.assertRaisesRegex(AgentBridgeError, "response id does not match"):
                session.execute("__result__ = 1", request_id="right")

    def test_agent_session_rejects_non_strict_json_response(self) -> None:
        command = _one_response_command('{"ok":true,"ok":true,"result":1}')
        with AgentSession.start("sample.i64", command=command) as session:
            with self.assertRaisesRegex(AgentBridgeError, "duplicate JSON object key"):
                session.execute("__result__ = 1")

    def test_agent_session_timeout_kills_hung_kernel(self) -> None:
        code = "import sys,time; sys.stdin.readline(); time.sleep(30)"
        with AgentSession.start("sample.i64", command=(sys.executable, "-B", "-c", code), request_timeout_s=0.2) as session:
            with self.assertRaisesRegex(AgentBridgeError, "timed out"):
                session.execute("__result__ = 1")
            self.assertIsNotNone(session._process.poll())


def _one_response_command(response: str) -> tuple[str, ...]:
    """Return a tiny protocol-shaped responder for bridge validation tests."""

    code = (
        "import sys;"
        "sys.stdin.readline();"
        f"sys.stdout.write({response + chr(10)!r});"
        "sys.stdout.flush()"
    )
    return (sys.executable, "-B", "-c", code)


if __name__ == "__main__":
    unittest.main()
