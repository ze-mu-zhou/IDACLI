"""Tests for per-run artifact storage."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
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
                    "artifact": "artifacts/nested/value.json",
                    "run_dir": str(store.run_dir.resolve()),
                    "size": len(expected),
                    "sha256": hashlib.sha256(expected).hexdigest(),
                },
            )

    def test_returned_metadata_locates_the_file_from_any_working_directory(self) -> None:
        """`run_dir / artifact` must resolve, whatever the reader's cwd is.

        The value handed to an agent used to be relative to the process
        working directory, which is the one thing the reader cannot observe:
        the path 404'd from the kernel's own cwd whenever runs_dir was
        absolute, and the two store constructors disagreed on the prefix.
        """
        for absolute_runs in (False, True):
            with self.subTest(absolute_runs=absolute_runs), tempfile.TemporaryDirectory() as temp_dir:
                runs = Path(temp_dir) / "runs" if absolute_runs else Path("runs")
                cwd = Path.cwd()
                os.chdir(temp_dir)
                try:
                    run_store = ArtifactStore.create(runs, run_id="locate")
                    flat_store = ArtifactStore.in_directory(Path(temp_dir) / "flat")
                    records = [
                        run_store.write_json("deep/nested/value.json", {"a": 1}),
                        run_store.write_jsonl("rows.jsonl", [{"a": 1}]),
                        flat_store.write_text("notes.txt", "hi"),
                    ]
                finally:
                    os.chdir(cwd)

                for metadata in records:
                    resolved = Path(metadata["run_dir"]) / metadata["artifact"]
                    self.assertTrue(resolved.is_file(), f"{resolved} does not exist")
                    self.assertEqual(resolved.stat().st_size, metadata["size"])

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
            self.assertEqual(metadata["artifact"], "artifacts/blobs/sample.bin")
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

    def test_rejects_parts_ending_in_dot_or_space(self) -> None:
        """Win32 strips trailing dots/spaces, so such parts must be rejected."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="trailing")
            bad_names = ["report.", "report ", "report. ", "a/b. /c"]

            for bad_name in bad_names:
                with self.subTest(bad_name=bad_name):
                    with self.assertRaises(ValueError):
                        store.write_binary(bad_name, b"x")

    def test_accepts_names_with_inner_dots_and_spaces(self) -> None:
        """Names with dots/spaces inside a component must stay legal."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="inner")

            metadata = store.write_binary("my report.v2", b"x")

            self.assertEqual((store.artifact_dir / "my report.v2").read_bytes(), b"x")
            self.assertEqual(metadata["artifact"], "artifacts/my report.v2")

    def test_trailing_dot_space_collision_is_rejected_at_write_time(self) -> None:
        """Names differing only by Win32-stripped suffixes must not silently collide."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="collide")

            first = store.write_binary("report", b"first")
            with self.assertRaises(ValueError):
                store.write_binary("report. ", b"second")

            on_disk = sorted(p.name for p in store.artifact_dir.iterdir())
            self.assertEqual(on_disk, ["report"])
            self.assertEqual((store.artifact_dir / "report").read_bytes(), b"first")
            self.assertEqual(first["artifact"], "artifacts/report")

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

    def test_in_directory_store_writes_text_with_local_prefix(self) -> None:
        """Directory-bound stores should write text under their own directory name."""
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "artifacts"
            store = ArtifactStore.in_directory(target)

            metadata = store.write_text("notes.txt", "hello\nworld")

            self.assertEqual((target / "notes.txt").read_text(encoding="utf-8"), "hello\nworld")
            self.assertEqual(metadata["artifact"], "notes.txt")
            self.assertEqual(metadata["size"], len("hello\nworld".encode("utf-8")))

    def test_escape_through_a_symlinked_container_is_refused_and_creates_nothing(self) -> None:
        """Containment must be decided before any directory is created.

        _ensure_inside is exercised 62 times by this suite but its raise
        never fired: every hostile name died earlier in the string validator
        _safe_relative_path, so stubbing the guard to a no-op left the suite
        green. A symlinked container is the one way to reach it -- and it
        also pins the ordering, since validating after mkdir(parents=True)
        refuses the write only once the directories already exist outside.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            store = ArtifactStore.in_directory(root / "art")
            outside = root / "outside"
            outside.mkdir()
            try:
                (store.artifact_dir / "nested").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation requires privileges on this host")

            with self.assertRaisesRegex(ValueError, "escapes the artifact directory"):
                store.write_binary("nested/deep/sub/payload.bin", b"\x00")

            self.assertEqual(list(outside.rglob("*")), [], "no directory may be created outside the store")

    def test_metadata_is_json_serializable(self) -> None:
        """Returned metadata should be ready for protocol response encoding."""
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="meta")

            metadata = store.write_binary("blob.bin", b"abc")

            self.assertIsInstance(json.dumps(metadata, sort_keys=True), str)


if __name__ == "__main__":
    unittest.main()
