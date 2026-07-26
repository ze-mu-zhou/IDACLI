"""Subprocess-level CLI contracts for byte-level stdin and protocol stdout."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _run_cli(payload: bytes, *, child_setup: str = "") -> subprocess.CompletedProcess[bytes]:
    """Run the real CLI in a child process with a byte-level stdin pipe."""
    child = (
        "import sys\n"
        + child_setup
        + "import ida_cli.__main__ as cli\n"
        + "from ida_cli.kernel import PythonOnlyBackend, create_session\n"
        + "cli.create_session = lambda target: create_session(target, backend=PythonOnlyBackend())\n"
        + "raise SystemExit(cli.main(['target.i64']))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    with tempfile.TemporaryDirectory() as temp_dir:
        return subprocess.run(
            [sys.executable, "-B", "-c", child],
            input=payload,
            capture_output=True,
            cwd=temp_dir,
            env=env,
            timeout=60,
        )


class CliSubprocessTests(unittest.TestCase):
    """Prove process-level failures degrade to envelopes, never tracebacks."""

    def test_undecodable_stdin_bytes_become_error_envelope_not_crash(self) -> None:
        payload = (
            b'{"id":1,"code":"__result__=1"}\n'
            b"\xff\xfe\n"
            b'{"id":2,"code":"__result__=2"}\n'
        )

        # Strict UTF-8 stdin: without lenient decoding the loop dies here.
        completed = _run_cli(payload, child_setup="sys.stdin.reconfigure(encoding='utf-8')\n")

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"Traceback", completed.stderr)
        envelopes = [
            json.loads(line)
            for line in completed.stdout.decode("utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(envelopes), 3, envelopes)
        self.assertTrue(envelopes[0]["ok"])
        self.assertEqual(envelopes[0]["id"], 1)
        self.assertFalse(envelopes[1]["ok"])
        self.assertEqual(envelopes[1]["error"]["type"], "JSONDecodeError")
        self.assertTrue(envelopes[2]["ok"])
        self.assertEqual(envelopes[2]["id"], 2)
        self.assertEqual(sum(1 for envelope in envelopes if not envelope["ok"]), 1)

    def test_fd_level_noise_does_not_corrupt_protocol_stdout(self) -> None:
        """Plugins writing banners to fd 1 (e.g. Keypatch) must not break JSONL."""
        request = {
            "id": 1,
            "code": "import os\nos.write(1, b'PLUGIN-BANNER\\n')\n__result__ = 42",
        }
        payload = (json.dumps(request) + "\n").encode("utf-8")

        completed = _run_cli(payload)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        envelopes = [
            json.loads(line)
            for line in completed.stdout.decode("utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(envelopes), 1, envelopes)
        self.assertEqual(envelopes[0]["result"], 42)
        self.assertNotIn(b"PLUGIN-BANNER", completed.stdout)
        self.assertIn(b"PLUGIN-BANNER", completed.stderr)

    def test_stray_thread_prints_never_reach_protocol_stdout(self) -> None:
        spawn = {
            "id": "spawn",
            "code": (
                "import threading, time\n"
                "def _stray():\n"
                "    time.sleep(0.2)\n"
                "    print('stray')\n"
                "_stray_thread = threading.Thread(target=_stray)\n"
                "_stray_thread.start()\n"
                "__result__ = 'spawned'"
            ),
        }
        join = {"id": "join", "code": "_stray_thread.join()\n__result__ = 42"}
        payload = (json.dumps(spawn) + "\n" + json.dumps(join) + "\n").encode("utf-8")

        completed = _run_cli(payload)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        stdout_text = completed.stdout.decode("utf-8")
        envelopes = [json.loads(line) for line in stdout_text.splitlines() if line.strip()]
        self.assertEqual([envelope["id"] for envelope in envelopes], ["spawn", "join"])
        self.assertNotIn("stray", stdout_text)
        self.assertIn("stray", completed.stderr.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
