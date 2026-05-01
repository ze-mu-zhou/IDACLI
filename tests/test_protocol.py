"""Tests for the AI-only JSONL protocol primitives."""

from __future__ import annotations

import io
import math
import sys
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ida_cli.protocol import (  # noqa: E402
    BadJsonError,
    RequestFormatError,
    bad_json_response,
    encode_jsonl,
    error_response,
    parse_request,
    success_response,
    write_jsonl,
)


class FlushCountingStream(io.StringIO):
    """Track protocol flushes. When modifying this, keep writes observable without stdout."""

    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()


class ProtocolTests(unittest.TestCase):
    """Verify stable protocol behavior. When adding tests, preserve stdout-only JSONL rules."""

    def test_encode_jsonl_is_compact_sorted_and_unicode_preserving(self) -> None:
        self.assertEqual(
            encode_jsonl({"z": 1, "a": {"text": "雪", "n": 2}}),
            '{"a":{"n":2,"text":"雪"},"z":1}\n',
        )

    def test_encode_jsonl_rejects_non_deterministic_nan(self) -> None:
        with self.assertRaises(ValueError):
            encode_jsonl({"bad": math.nan})

    def test_encode_jsonl_rejects_non_object_protocol_messages(self) -> None:
        with self.assertRaises(TypeError):
            encode_jsonl(["not", "an", "envelope"])

    def test_parse_minimal_request_and_success_omits_missing_id(self) -> None:
        request = parse_request('{"code":"__result__ = 1"}\n')

        response = success_response(request, result=1, stdout="out", stderr="", elapsed_ms=3)

        self.assertEqual(request.code, "__result__ = 1")
        self.assertFalse(request.has_id)
        self.assertEqual(request.bindings, {})
        self.assertNotIn("id", response)
        self.assertEqual(
            response,
            {"elapsed_ms": 3, "ok": True, "result": 1, "stderr": "", "stdout": "out"},
        )

    def test_parse_request_preserves_optional_bindings_object(self) -> None:
        request = parse_request('{"id":"req-1","code":"__result__ = __shard_index__","bindings":{"__shard_index__":7}}')

        self.assertEqual(request.request_id, "req-1")
        self.assertEqual(request.bindings, {"__shard_index__": 7})

    def test_request_id_is_passed_through_exactly_when_present(self) -> None:
        request = parse_request('{"id":{"agent":"worker-1","seq":7},"code":"pass"}')

        response = success_response(request, result=None)

        self.assertTrue(request.has_id)
        self.assertEqual(request.request_id, {"agent": "worker-1", "seq": 7})
        self.assertEqual(response["id"], {"agent": "worker-1", "seq": 7})

    def test_explicit_null_request_id_is_preserved(self) -> None:
        request = parse_request('{"id":null,"code":"pass"}')

        response = success_response(request)

        self.assertTrue(request.has_id)
        self.assertIsNone(response["id"])

    def test_error_response_keeps_request_id_and_captured_streams(self) -> None:
        request = parse_request('{"id":"req-2","code":"x"}')

        response = error_response(
            request,
            error_type="NameError",
            message="name 'x' is not defined",
            traceback="Traceback text",
            stdout="printed",
            stderr="warned",
            elapsed_ms=9,
        )

        self.assertEqual(
            response,
            {
                "elapsed_ms": 9,
                "error": {
                    "message": "name 'x' is not defined",
                    "traceback": "Traceback text",
                    "type": "NameError",
                },
                "id": "req-2",
                "ok": False,
                "stderr": "warned",
                "stdout": "printed",
            },
        )

    def test_bad_json_response_is_structured_without_request_id(self) -> None:
        with self.assertRaises(BadJsonError) as caught:
            parse_request('{"id":"req" "code":"pass"}')

        response = bad_json_response(caught.exception, elapsed_ms=1)

        self.assertNotIn("id", response)
        self.assertEqual(response["ok"], False)
        self.assertEqual(response["error"]["type"], "JSONDecodeError")
        self.assertEqual(response["error"]["line"], 1)
        self.assertGreaterEqual(response["error"]["column"], 1)
        self.assertGreaterEqual(response["error"]["position"], 0)

    def test_parse_request_rejects_invalid_protocol_shapes(self) -> None:
        invalid_lines = [
            "[]",
            '{"id":"req"}',
            '{"code":7}',
            '{"code":"pass","bindings":[]}',
        ]

        for line in invalid_lines:
            with self.subTest(line=line):
                with self.assertRaises(RequestFormatError):
                    parse_request(line)

    def test_parse_request_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(BadJsonError):
            parse_request('{"code":"a","code":"b"}')

    def test_parse_request_rejects_non_standard_json_constants(self) -> None:
        with self.assertRaises(BadJsonError) as caught:
            parse_request('{"code":"pass","id":NaN}')

        self.assertIn("invalid JSON constant", caught.exception.message)

    def test_write_jsonl_writes_one_line_and_flushes(self) -> None:
        stream = FlushCountingStream()

        write_jsonl(stream, {"ok": True, "result": None})

        self.assertEqual(stream.getvalue(), '{"ok":true,"result":null}\n')
        self.assertEqual(stream.flush_count, 1)


if __name__ == "__main__":
    unittest.main()
