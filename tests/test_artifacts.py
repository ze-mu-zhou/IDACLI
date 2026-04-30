"""Tests for per-run artifact storage."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ida_cli.artifacts import ArtifactStore


class ArtifactStoreTests(unittest.TestCase):
    """Verify artifact writes stay deterministic, safe, and protocol-silent."""

    def test_create_run_store_and_write_json_metadata(self) -> None:
        """JSON artifacts should be deterministic and metadata-addressable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="sample")

            metadata = store.write_json("nested/value.json", {"b": 2, "a": [1]})

            artifact = store.artifact_dir / "nested" / "value.json"
            expected = b'{"a":[1],"b":2}'
            self.assertEqual(artifact.read_bytes(), expected)
            self.assertEqual(
                metadata,
                {
                    "artifact": "runs/sample/artifacts/nested/value.json",
                    "size": len(expected),
                    "sha256": hashlib.sha256(expected).hexdigest(),
                },
            )

    def test_write_jsonl_counts_rows_and_hashes_exact_bytes(self) -> None:
        """JSONL artifacts should count rows and hash newline-delimited bytes."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="jsonl")

            metadata = store.write_jsonl("rows.jsonl", [{"ea": 2}, {"ea": 1}])

            expected = b'{"ea":2}\n{"ea":1}\n'
            self.assertEqual((store.artifact_dir / "rows.jsonl").read_bytes(), expected)
            self.assertEqual(metadata["size"], len(expected))
            self.assertEqual(metadata["count"], 2)
            self.assertEqual(metadata["sha256"], hashlib.sha256(expected).hexdigest())

    def test_write_binary_preserves_bytes_and_uses_safe_slashes(self) -> None:
        """Binary artifacts should preserve payloads and normalize metadata paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="bin")
            payload = b"\x00IDA\xff"

            metadata = store.write_binary(r"blobs\sample.bin", payload)

            self.assertEqual((store.artifact_dir / "blobs" / "sample.bin").read_bytes(), payload)
            self.assertEqual(metadata["artifact"], "runs/bin/artifacts/blobs/sample.bin")
            self.assertEqual(metadata["size"], len(payload))
            self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())

    def test_rejects_unsafe_relative_paths(self) -> None:
        """Artifact names should reject absolute, traversal, and device paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="safe")
            bad_names = [
                "",
                ".",
                "./out.bin",
                "out/",
                "nested//out.bin",
                "../out.bin",
                "nested/../out.bin",
                "C:/out.bin",
                "//host/share/out.bin",
                "CON",
            ]

            for bad_name in bad_names:
                with self.subTest(bad_name=bad_name):
                    with self.assertRaises(ValueError):
                        store.write_binary(bad_name, b"x")

    def test_failed_jsonl_write_does_not_replace_existing_artifact(self) -> None:
        """Serialization failures should leave prior artifact bytes intact."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="atomic")
            store.write_jsonl("rows.jsonl", [{"ok": True}])
            artifact = store.artifact_dir / "rows.jsonl"
            original = artifact.read_bytes()

            with self.assertRaises(TypeError):
                store.write_jsonl("rows.jsonl", [{"bad": {1, 2, 3}}])

            self.assertEqual(artifact.read_bytes(), original)

    def test_writes_do_not_pollute_stdout(self) -> None:
        """Artifact helpers must not write human logs to process stdout."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="silent")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                store.write_json("value.json", {"answer": 42})
                store.write_jsonl("rows.jsonl", [{"answer": 42}])
                store.write_binary("blob.bin", b"answer")

            self.assertEqual(stdout.getvalue(), "")

    def test_json_writer_rejects_non_strict_json_numbers(self) -> None:
        """JSON artifacts should fail fast instead of emitting non-standard NaN."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="strict")

            with self.assertRaises(ValueError):
                store.write_json("nan.json", {"value": float("nan")})

            self.assertFalse((store.artifact_dir / "nan.json").exists())

    def test_metadata_is_json_serializable(self) -> None:
        """Returned metadata should be ready for protocol response encoding."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="meta")

            metadata = store.write_binary("blob.bin", b"abc")

            self.assertIsInstance(json.dumps(metadata, sort_keys=True), str)


if __name__ == "__main__":
    unittest.main()
