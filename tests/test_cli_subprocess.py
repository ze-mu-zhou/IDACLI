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


def _run_cli(
    payload: bytes,
    *,
    child_setup: str = "",
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
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
    if env_overrides:
        env.update(env_overrides)
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

        # No child_setup: the kernel must pin UTF-8 itself. Forcing the codec
        # here would hide whether it does -- that shim is what let a locale
        # mismatch corrupt every non-ASCII request past 258 green tests.
        completed = _run_cli(payload)

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

    def test_non_ascii_request_survives_a_non_utf8_host_locale(self) -> None:
        """Requests are UTF-8 on the wire regardless of the host codepage.

        Everything else already pins UTF-8 (encode_jsonl, the agent bridge,
        both daemon makefiles, the protocol stdout); leaving stdio to the
        locale silently re-decoded non-ASCII into *different valid*
        characters and still answered ok=true, so a comment or rename landed
        in the database as mojibake.
        """
        text = "安全 café реверс"
        payload = (json.dumps({"id": 1, "code": f"__result__ = {text!r}"}, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )

        for codepage in ("cp936", "cp1252", "utf-8"):
            with self.subTest(codepage=codepage):
                completed = _run_cli(payload, env_overrides={"PYTHONIOENCODING": codepage})

                self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
                envelope = json.loads(completed.stdout.decode("utf-8").splitlines()[-1])
                self.assertTrue(envelope["ok"], envelope)
                # Compare codepoints: a mismatch here is silent data corruption.
                self.assertEqual(envelope["result"], text)


if __name__ == "__main__":
    unittest.main()
