"""Tests for the explicit cache and index layer."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_cli.cache import CacheError, IDACache, load_persistent_cache


class FakeCacheProvider:
    """IDA-shaped provider that keeps cache tests independent from IDA."""

    def __init__(self, fingerprint: dict[str, object] | None = None) -> None:
        # Count expensive calls; future changes must preserve repeated-read cache wins.
        self.decompile_calls = 0
        self.refresh_reads = 0
        self.extra_names: list[tuple[int, str]] = [(0x1000, "main")]
        self._fingerprint = dict(fingerprint) if fingerprint is not None else None

    def fingerprint(self) -> dict[str, object]:
        """Return the fake database fingerprint, mirroring None-safe IDA lookups."""

        if self._fingerprint is None:
            return {"root_filename": None, "input_md5": None}
        return dict(self._fingerprint)

    def functions(self) -> list[dict[str, object]]:
        """Return deterministic function records."""

        self.refresh_reads += 1
        return [
            {"ea": 0x1000, "name": "main", "end_ea": 0x1010},
            {"ea": 0x1100, "name": "helper", "end_ea": 0x1110},
        ]

    def names(self) -> list[tuple[int, str]]:
        """Return IDA-style name tuples."""

        return list(self.extra_names)

    def strings(self) -> list[dict[str, object]]:
        """Return deterministic string records."""

        return [{"ea": 0x3000, "length": 5, "type": 0, "value": "hello"}]

    def imports(self) -> list[dict[str, object]]:
        """Return deterministic import records."""

        return [{"ea": 0x5000, "module": "msvcrt", "name": "puts", "ordinal": 7}]

    def xrefs_to(self, ea: int) -> list[dict[str, object]]:
        """Return incoming xrefs for strings and imports."""

        table = {
            0x3000: [{"frm": 0x1004, "to": 0x3000, "type": 1, "iscode": False}],
            0x5000: [{"frm": 0x1008, "to": 0x5000, "type": 17, "iscode": True}],
        }
        return list(table.get(ea, []))

    def function_items(self, function: dict[str, object]) -> list[int]:
        """Return item addresses so call edges cover the whole function."""

        start = int(function["ea"])
        return [start, start + 4, start + 8]

    def xrefs_from(self, ea: int) -> list[dict[str, object]]:
        """Return outgoing xrefs from selected instruction addresses."""

        table = {
            0x1004: [{"frm": 0x1004, "to": 0x1100, "type": 17, "iscode": True}],
            0x1008: [{"frm": 0x1008, "to": 0x5000, "type": 17, "iscode": True}],
        }
        return list(table.get(ea, []))

    def decompile(self, ea: int) -> dict[str, object]:
        """Return pseudocode and record lazy call counts."""

        self.decompile_calls += 1
        return {"ea": ea, "name": "main" if ea == 0x1000 else "helper", "pseudocode": f"func_{ea:x}();"}


class FakeArtifactWriter:
    """Capture artifact exports without touching IDA or real run directories."""

    def __init__(self) -> None:
        # Keep the last payload visible; future changes must preserve export shape.
        self.name: str | None = None
        self.payload: dict[str, object] | None = None

    def write_json(self, name: str, value: dict[str, object]) -> dict[str, object]:
        """Store the payload and return ArtifactStore-shaped metadata."""

        self.name = name
        self.payload = value
        return {"artifact": f"runs/sample/artifacts/{name}", "size": 123, "sha256": "abc"}


class MissingCallScopeProvider(FakeCacheProvider):
    """Provider missing the explicit full-function call-edge surface."""

    @property
    def function_items(self) -> object:
        """Hide inherited function item support for fail-fast coverage."""

        raise AttributeError


class CacheTests(unittest.TestCase):
    """Verify cache behavior through injected fake providers."""

    def test_refresh_builds_function_name_ref_and_call_indexes(self) -> None:
        provider = FakeCacheProvider()
        cache = IDACache(provider)

        status = cache.refresh()

        self.assertFalse(status["stale"])
        self.assertEqual(cache.functions()[0]["name"], "main")
        self.assertEqual(cache.name_to_address()["msvcrt!puts"], 0x5000)
        self.assertEqual(cache.get_ea("0x1100"), 0x1100)
        self.assertEqual(cache.address_to_function(0x1005)["name"], "main")
        self.assertEqual(cache.string_refs()[0]["ref_functions"], [0x1000])
        self.assertEqual(cache.import_refs()[0]["refs"][0]["frm"], 0x1008)
        self.assertEqual(cache.call_edges("main")[0]["callee"], 0x1100)
        self.assertTrue(cache.call_edges("main")[1]["external"])

    def test_stale_access_fails_until_explicit_refresh(self) -> None:
        provider = FakeCacheProvider()
        cache = IDACache(provider)
        cache.refresh()
        reads_after_refresh = provider.refresh_reads

        cache.mark_stale("rename applied")

        with self.assertRaisesRegex(CacheError, "call refresh"):
            cache.functions()
        self.assertEqual(provider.refresh_reads, reads_after_refresh)
        self.assertTrue(cache.status()["stale"])
        cache.refresh()
        self.assertFalse(cache.status()["stale"])

    def test_lazy_decompile_caches_and_refresh_clears_pseudocode(self) -> None:
        provider = FakeCacheProvider()
        cache = IDACache(provider)
        cache.refresh()

        first = cache.decompile("main")
        second = cache.decompile(0x1002)

        self.assertEqual(first, second)
        self.assertEqual(provider.decompile_calls, 1)
        cache.refresh()
        cache.decompile("main")
        self.assertEqual(provider.decompile_calls, 2)

    def test_export_artifact_uses_injected_writer_and_stable_payload_shape(self) -> None:
        provider = FakeCacheProvider()
        writer = FakeArtifactWriter()
        cache = IDACache(provider)
        cache.refresh()
        cache.decompile("main")

        metadata = cache.export_artifact(writer)

        self.assertEqual(writer.name, "cache/index.json")
        self.assertIsNotNone(writer.payload)
        self.assertEqual(writer.payload["schema"], "ida-cli-cache-index-v1")
        self.assertEqual(writer.payload["counts"]["decompiled"], 1)
        self.assertEqual(writer.payload["address_to_function"][0]["function_ea"], 0x1000)
        self.assertEqual(metadata["artifact"]["artifact"], "runs/sample/artifacts/cache/index.json")
        self.assertEqual(metadata["counts"]["call_edges"], 2)

    def test_persistent_cache_round_trips_without_provider_reads(self) -> None:
        provider = FakeCacheProvider()
        cache = IDACache(provider)
        cache.refresh()
        cache.decompile("main")

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache" / "index.json"
            saved = cache.save_persistent(path)
            loaded = load_persistent_cache(FakeCacheProvider(), path)

            self.assertEqual(saved["path"], str(path))
            self.assertFalse(loaded.status()["stale"])
            self.assertEqual(loaded.functions()[0]["name"], "main")
            self.assertEqual(loaded.decompile("main")["pseudocode"], "func_1000();")

    def test_persistent_cache_rejects_wrong_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text('{"kind":"wrong","payload":{}}', encoding="utf-8")

            with self.assertRaisesRegex(CacheError, "kind mismatch"):
                IDACache(FakeCacheProvider()).load_persistent(path)

    def test_persistent_cache_matching_fingerprint_loads(self) -> None:
        fingerprint = {"root_filename": "/bin/sample", "input_md5": "abc123"}
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            cache = IDACache(FakeCacheProvider(fingerprint=fingerprint))
            cache.refresh()
            cache.save_persistent(path)

            loaded = load_persistent_cache(FakeCacheProvider(fingerprint=fingerprint), path)

            self.assertFalse(loaded.status()["stale"])
            self.assertEqual(loaded.functions()[0]["name"], "main")

    def test_persistent_cache_fingerprint_mismatch_requires_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            cache = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/a", "input_md5": "aaa"}))
            cache.refresh()
            cache.save_persistent(path)

            other = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/b", "input_md5": "bbb"}))
            with self.assertRaisesRegex(CacheError, "fingerprint mismatch"):
                other.load_persistent(path)
            self.assertTrue(other.status()["stale"])

            forced = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/b", "input_md5": "bbb"}))
            forced.load_persistent(path, force=True)
            self.assertFalse(forced.status()["stale"])
            self.assertEqual(forced.functions()[0]["name"], "main")

    def test_persistent_cache_allows_missing_fingerprint_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            cache = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/a", "input_md5": "aaa"}))
            cache.refresh()
            cache.save_persistent(path)

            with self.subTest(case="current side lacks data"):
                loaded = IDACache(FakeCacheProvider())
                loaded.load_persistent(path)
                self.assertFalse(loaded.status()["stale"])

            with self.subTest(case="stored side lacks data"):
                plain_path = Path(temp_dir) / "plain.json"
                plain = IDACache(FakeCacheProvider())
                plain.refresh()
                plain.save_persistent(plain_path)
                loaded = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/a"}))
                loaded.load_persistent(plain_path)
                self.assertFalse(loaded.status()["stale"])

            with self.subTest(case="legacy envelope without fingerprint key"):
                wrapper = json.loads(path.read_text(encoding="utf-8"))
                del wrapper["fingerprint"]
                legacy_path = Path(temp_dir) / "legacy.json"
                legacy_path.write_text(json.dumps(wrapper), encoding="utf-8")
                loaded = IDACache(FakeCacheProvider(fingerprint={"root_filename": "/bin/other"}))
                loaded.load_persistent(legacy_path)
                self.assertFalse(loaded.status()["stale"])

    def test_get_ea_accepts_leading_zero_decimal_and_rejects_badaddr(self) -> None:
        cache = IDACache(FakeCacheProvider())
        cache.refresh()

        self.assertEqual(cache.get_ea("010"), 10)
        with self.assertRaisesRegex(CacheError, "invalid effective address"):
            cache.get_ea((1 << 64) - 1)
        with self.assertRaisesRegex(CacheError, "invalid effective address"):
            cache.get_ea("0xFFFFFFFFFFFFFFFF")

    def test_refresh_fails_fast_on_ambiguous_duplicate_names(self) -> None:
        provider = FakeCacheProvider()
        provider.extra_names = [(0x1111, "main")]
        cache = IDACache(provider)

        with self.assertRaisesRegex(CacheError, "duplicate name"):
            cache.refresh()
        self.assertTrue(cache.status()["stale"])

    def test_call_edge_provider_must_cover_function_scope_explicitly(self) -> None:
        cache = IDACache(MissingCallScopeProvider())

        with self.assertRaisesRegex(CacheError, "call edge cache requires"):
            cache.refresh()


if __name__ == "__main__":
    unittest.main()
