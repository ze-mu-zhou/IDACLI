"""Tests for the explicit cache and index layer."""

from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_cli.cache import CacheError, IDACache, load_persistent_cache


def fake_ida_nalt(
    *, root_filename: str = "chall", md5: bytes | str | None = None, size: int | None = None
) -> types.ModuleType:
    """Build a stand-in ida_nalt module for database fingerprint tests.

    The fingerprint imports IDA lazily, so a stub in sys.modules is the only
    way to cover the real IDA 9 API on a host without IDA on the import
    path: get_root_filename() -> str, retrieve_input_file_md5() -> raw
    digest bytes (never hex text) and retrieve_input_file_size() -> int.
    Leaving md5 or size out mirrors a build whose getter is missing, which
    must degrade to a None field rather than raise; passing md5 as text
    mirrors a build that already returns hex.
    """

    module = types.ModuleType("ida_nalt")
    module.get_root_filename = lambda: root_filename
    if md5 is not None:
        module.retrieve_input_file_md5 = lambda: md5
    if size is not None:
        module.retrieve_input_file_size = lambda: size
    return module


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
        return {"artifact": name, "size": 123, "sha256": "abc"}


class MissingCallScopeProvider(FakeCacheProvider):
    """Provider missing the explicit full-function call-edge surface."""

    @property
    def function_items(self) -> object:
        """Hide inherited function item support for fail-fast coverage."""

        raise AttributeError


class ConflictingImportProvider(FakeCacheProvider):
    """Provider whose function shares its name with an import thunk."""

    def functions(self) -> list[dict[str, object]]:
        """Return one function named like the printf import thunk."""

        return [{"ea": 0x1000, "name": "printf", "end_ea": 0x1010}]

    def imports(self) -> list[dict[str, object]]:
        """Return the printf import thunk living at a different address."""

        return [{"ea": 0x2000, "module": "msvcrt", "name": "printf", "ordinal": 11}]


class DuplicateFunctionNameProvider(FakeCacheProvider):
    """Provider with two distinct functions sharing one name."""

    def functions(self) -> list[dict[str, object]]:
        """Return two same-named functions at different addresses."""

        return [
            {"ea": 0x1000, "name": "worker", "end_ea": 0x1010},
            {"ea": 0x2000, "name": "worker", "end_ea": 0x2010},
        ]


class DuplicateFunctionStartProvider(FakeCacheProvider):
    """Provider reporting two function records for one start address."""

    def functions(self) -> list[dict[str, object]]:
        """Return corrupted provider data with a duplicate function start."""

        return [
            {"ea": 0x1000, "name": "main", "end_ea": 0x1010},
            {"ea": 0x1000, "name": "main_alias", "end_ea": 0x1020},
        ]


class IDAFingerprintProvider(FakeCacheProvider):
    """Provider that leaves database identity to the real IDA lookups.

    Hides the inherited fingerprint hook so the cache takes the ida_nalt
    path, which is the only path production ever uses: no provider in the
    package implements a fingerprint hook.
    """

    @property
    def fingerprint(self) -> object:
        """Hide the inherited hook so the IDA module lookups run instead."""

        raise AttributeError


class NoReindexProvider:
    """Provider whose every index read fails, so loads must use the file.

    load_persistent exists to skip a multi-minute re-index, so a round-trip
    test handed a provider that can rebuild the same data cannot tell a real
    file load from a silent live re-index. Only the fingerprint lookup is
    allowed: a persistent load queries it on purpose to detect a foreign
    database. Deliberately not a FakeCacheProvider subclass -- a provider
    surface added later must fail loudly here instead of being inherited in
    working form.
    """

    def fingerprint(self) -> dict[str, object]:
        """Return the one cheap live lookup a persistent load may make."""

        return {"root_filename": None, "input_md5": None}

    def functions(self) -> list[dict[str, object]]:
        """Fail instead of rebuilding the function index."""

        raise AssertionError("persistent load must not call functions()")

    def names(self) -> list[tuple[int, str]]:
        """Fail instead of rebuilding the name index."""

        raise AssertionError("persistent load must not call names()")

    def strings(self) -> list[dict[str, object]]:
        """Fail instead of rebuilding the string index."""

        raise AssertionError("persistent load must not call strings()")

    def imports(self) -> list[dict[str, object]]:
        """Fail instead of rebuilding the import index."""

        raise AssertionError("persistent load must not call imports()")

    def xrefs_to(self, ea: int) -> list[dict[str, object]]:
        """Fail instead of re-reading incoming xrefs."""

        raise AssertionError(f"persistent load must not call xrefs_to(0x{ea:x})")

    def xrefs_from(self, ea: int) -> list[dict[str, object]]:
        """Fail instead of re-reading outgoing xrefs."""

        raise AssertionError(f"persistent load must not call xrefs_from(0x{ea:x})")

    def function_items(self, function: dict[str, object]) -> list[int]:
        """Fail instead of re-walking function items for call edges."""

        raise AssertionError("persistent load must not call function_items()")

    def decompile(self, ea: int) -> dict[str, object]:
        """Fail instead of re-decompiling a function already in the snapshot."""

        raise AssertionError(f"persistent load must not call decompile(0x{ea:x})")


class ModulelessImportProvider(FakeCacheProvider):
    """Provider whose import record lacks a module name."""

    def imports(self) -> list[dict[str, object]]:
        """Return an import without module qualification."""

        return [{"ea": 0x5000, "module": None, "name": "puts", "ordinal": 7}]


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
        self.assertEqual(metadata["artifact"]["artifact"], "cache/index.json")
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

    def test_persistent_load_serves_file_data_instead_of_a_live_reindex(self) -> None:
        # The whole point of load_cache is skipping a multi-minute re-index,
        # so every index has to come out of the file. A provider that refuses
        # every index read is the only way to prove that: with a cooperative
        # provider, blanking an index in the load path is invisible because
        # the assertions are equally satisfiable by a fresh refresh.
        source = IDACache(FakeCacheProvider())
        source.refresh()
        source.decompile("main")

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            source.save_persistent(path)

            loaded = load_persistent_cache(NoReindexProvider(), path)

            self.assertEqual([row["ea"] for row in loaded.functions()], [0x1000, 0x1100])
            self.assertEqual(loaded.name_to_address(), {"helper": 0x1100, "main": 0x1000, "msvcrt!puts": 0x5000})
            self.assertEqual([row["value"] for row in loaded.string_refs()], ["hello"])
            self.assertEqual(
                loaded.string_refs()[0]["refs"], [{"frm": 0x1004, "to": 0x3000, "type": 1, "iscode": False}]
            )
            self.assertEqual(loaded.string_refs()[0]["ref_functions"], [0x1000])
            self.assertEqual([row["name"] for row in loaded.import_refs()], ["puts"])
            self.assertEqual(loaded.import_refs()[0]["refs"][0]["frm"], 0x1008)
            self.assertEqual(loaded.import_refs()[0]["ref_functions"], [0x1000])
            self.assertEqual(
                [(edge["caller"], edge["target"], edge["callee"], edge["external"]) for edge in loaded.call_edges()],
                [(0x1000, 0x1100, 0x1100, False), (0x1000, 0x5000, None, True)],
            )
            self.assertEqual(loaded.call_edges("main"), loaded.call_edges())
            self.assertEqual(loaded.address_to_function(0x1105)["name"], "helper")
            self.assertEqual(loaded.decompile("main")["pseudocode"], "func_1000();")

    def persisted_fingerprint(self, module: types.ModuleType | None) -> dict[str, object]:
        """Save a snapshot under one ida_nalt stub and return its stored fingerprint."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            cache = IDACache(IDAFingerprintProvider())
            with mock.patch.dict(sys.modules, {"ida_nalt": module}):
                cache.refresh()
                cache.save_persistent(path)
            return json.loads(path.read_text(encoding="utf-8"))["fingerprint"]

    def test_database_fingerprint_uses_the_ida9_hash_and_size_apis(self) -> None:
        # idc.get_input_md5 does not exist in IDA 9, so the md5 leg silently
        # produced None forever and left the bare base name as the only
        # discriminator. The digest must be persisted as hex text, not as the
        # repr of raw bytes; fields are stringified on both sides so the saved
        # and current forms stay comparable, so the size persists as text too.
        self.assertEqual(
            self.persisted_fingerprint(fake_ida_nalt(md5=b"\xab" * 16, size=4096)),
            {"root_filename": "chall", "input_md5": "ab" * 16, "input_size": "4096"},
        )

    def test_database_fingerprint_drops_fields_this_session_cannot_compute(self) -> None:
        # A field the session cannot produce must become None, which
        # _check_fingerprint skips: refusing instead would break every
        # snapshot written before a field existed.
        with self.subTest(case="hash getters absent"):
            self.assertEqual(
                self.persisted_fingerprint(fake_ida_nalt()),
                {"root_filename": "chall", "input_md5": None, "input_size": None},
            )

        with self.subTest(case="database never recorded a hash"):
            self.assertIsNone(self.persisted_fingerprint(fake_ida_nalt(md5=b"", size=4096))["input_md5"])

        with self.subTest(case="size sentinel"):
            # IDA 9 answers 0 with no database loaded; recording "0" would
            # make every later session with a real size refuse the snapshot.
            self.assertIsNone(self.persisted_fingerprint(fake_ida_nalt(md5=b"\xab" * 16, size=0))["input_size"])

        with self.subTest(case="empty root filename"):
            # "" is not a base name any session could match; it has to be
            # skipped like a missing field instead of compared.
            self.assertIsNone(self.persisted_fingerprint(fake_ida_nalt(root_filename=""))["root_filename"])

        with self.subTest(case="build already returns hex text"):
            self.assertEqual(self.persisted_fingerprint(fake_ida_nalt(md5="AB" * 16))["input_md5"], "ab" * 16)

        with self.subTest(case="no IDA on the import path"):
            # None in sys.modules makes the lazy import raise ImportError on
            # every host, including one that really has idalib installed.
            self.assertEqual(
                self.persisted_fingerprint(None),
                {"root_filename": None, "input_md5": None, "input_size": None},
            )

    def test_persistent_cache_refuses_a_same_named_binary_with_another_hash(self) -> None:
        # Two CTF binaries both named "chall" (or v1/app.exe and v2/app.exe):
        # the base name matches, so only the content hash and size can tell
        # them apart. Loading one snapshot over the other would silently serve
        # the wrong function index, name map and pseudocode.
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cache.json"
            with mock.patch.dict(sys.modules, {"ida_nalt": fake_ida_nalt(md5=b"\xaa" * 16, size=4096)}):
                cache = IDACache(IDAFingerprintProvider())
                cache.refresh()
                cache.save_persistent(path)

            with mock.patch.dict(sys.modules, {"ida_nalt": fake_ida_nalt(md5=b"\xbb" * 16, size=8192)}):
                other = IDACache(IDAFingerprintProvider())
                with self.assertRaisesRegex(CacheError, "fingerprint mismatch: input_md5, input_size"):
                    other.load_persistent(path)
                self.assertTrue(other.status()["stale"])

                forced = load_persistent_cache(IDAFingerprintProvider(), path, force=True)
                self.assertFalse(forced.status()["stale"])
                self.assertEqual(forced.functions()[0]["name"], "main")

    def test_persistent_cache_keeps_loading_snapshots_saved_without_a_hash(self) -> None:
        # Every snapshot this tool has written so far stores "input_md5": null
        # and no input_size at all, and an older IDA may lack the getters
        # entirely. Neither side missing a field may ever refuse a load.
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "legacy.json"
            legacy = IDACache(FakeCacheProvider(fingerprint={"root_filename": "chall", "input_md5": None}))
            legacy.refresh()
            legacy.save_persistent(path)
            self.assertIsNone(json.loads(path.read_text(encoding="utf-8"))["fingerprint"]["input_md5"])

            with self.subTest(case="stored snapshot has no hash"):
                with mock.patch.dict(sys.modules, {"ida_nalt": fake_ida_nalt(md5=b"\xaa" * 16, size=4096)}):
                    loaded = load_persistent_cache(IDAFingerprintProvider(), path)
                self.assertFalse(loaded.status()["stale"])
                self.assertEqual(loaded.functions()[0]["name"], "main")

            with self.subTest(case="this session cannot hash the input"):
                hashed = Path(temp_dir) / "hashed.json"
                with mock.patch.dict(sys.modules, {"ida_nalt": fake_ida_nalt(md5=b"\xaa" * 16, size=4096)}):
                    cache = IDACache(IDAFingerprintProvider())
                    cache.refresh()
                    cache.save_persistent(hashed)
                with mock.patch.dict(sys.modules, {"ida_nalt": fake_ida_nalt()}):
                    loaded = load_persistent_cache(IDAFingerprintProvider(), hashed)
                self.assertFalse(loaded.status()["stale"])
                self.assertEqual(loaded.functions()[0]["name"], "main")

    def test_get_ea_accepts_leading_zero_decimal_and_rejects_badaddr(self) -> None:
        cache = IDACache(FakeCacheProvider())
        cache.refresh()

        self.assertEqual(cache.get_ea("010"), 10)
        with self.assertRaisesRegex(CacheError, "invalid effective address"):
            cache.get_ea((1 << 64) - 1)
        with self.assertRaisesRegex(CacheError, "invalid effective address"):
            cache.get_ea("0xFFFFFFFFFFFFFFFF")

    def test_duplicate_names_become_ambiguous_without_failing_refresh(self) -> None:
        provider = FakeCacheProvider()
        provider.extra_names = [(0x1111, "main")]
        cache = IDACache(provider)

        status = cache.refresh()

        self.assertFalse(status["stale"])
        self.assertNotIn("main", cache.name_to_address())
        self.assertEqual(cache.ambiguous_names, {"main": [0x1000, 0x1111]})
        with self.assertRaisesRegex(CacheError, "ambiguous"):
            cache.get_ea("main")

    def test_function_and_import_sharing_name_become_ambiguous(self) -> None:
        cache = IDACache(ConflictingImportProvider())

        status = cache.refresh()

        self.assertFalse(status["stale"])
        names = cache.name_to_address()
        self.assertNotIn("printf", names)
        self.assertEqual(names["msvcrt!printf"], 0x2000)
        self.assertEqual(cache.ambiguous_names, {"printf": [0x1000, 0x2000]})
        self.assertEqual(cache.get_ea("msvcrt!printf"), 0x2000)
        with self.assertRaisesRegex(CacheError, r"ambiguous.*0x1000.*0x2000"):
            cache.get_ea("printf")

    def test_same_named_functions_become_ambiguous(self) -> None:
        cache = IDACache(DuplicateFunctionNameProvider())

        status = cache.refresh()

        self.assertFalse(status["stale"])
        self.assertNotIn("worker", cache.name_to_address())
        self.assertEqual(cache.ambiguous_names, {"worker": [0x1000, 0x2000]})
        with self.assertRaisesRegex(CacheError, "ambiguous"):
            cache.get_ea("worker")

    def test_same_address_duplicate_names_resolve_normally(self) -> None:
        cache = IDACache(FakeCacheProvider())

        cache.refresh()

        self.assertEqual(cache.name_to_address()["main"], 0x1000)
        self.assertEqual(cache.ambiguous_names, {})

    def test_import_bare_name_resolves_only_in_qualified_form(self) -> None:
        cache = IDACache(FakeCacheProvider())

        cache.refresh()

        names = cache.name_to_address()
        self.assertNotIn("puts", names)
        self.assertEqual(names["msvcrt!puts"], 0x5000)
        self.assertEqual(cache.ambiguous_names, {})
        with self.assertRaisesRegex(CacheError, "not present"):
            cache.get_ea("puts")

    def test_import_without_module_registers_no_name(self) -> None:
        cache = IDACache(ModulelessImportProvider())

        status = cache.refresh()

        self.assertFalse(status["stale"])
        self.assertNotIn("puts", cache.name_to_address())
        self.assertEqual(cache.ambiguous_names, {})

    def test_duplicate_function_start_still_fails_refresh(self) -> None:
        cache = IDACache(DuplicateFunctionStartProvider())

        with self.assertRaisesRegex(CacheError, "duplicate function start"):
            cache.refresh()
        self.assertTrue(cache.status()["stale"])

    def test_call_edge_provider_must_cover_function_scope_explicitly(self) -> None:
        cache = IDACache(MissingCallScopeProvider())

        with self.assertRaisesRegex(CacheError, "call edge cache requires"):
            cache.refresh()

    def test_reads_hand_out_copies_that_cannot_corrupt_the_indexes(self) -> None:
        # The read path trades copy.deepcopy for a JSON-shaped walker plus
        # shallow copies where normalization guarantees flat rows; that is
        # only sound while every returned container stays detached.
        cache = IDACache(FakeCacheProvider())
        cache.refresh()
        before = {
            "functions": cache.functions(),
            "string_refs": cache.string_refs(),
            "import_refs": cache.import_refs(),
            "call_edges": cache.call_edges(),
            "export": cache.export(),
        }

        cache.functions()[0]["name"] = "corrupted"
        cache.functions().clear()
        cache.address_to_function(0x1000)["ea"] = -1
        string_refs = cache.string_refs()
        string_refs[0]["refs"][0]["frm"] = -1
        string_refs[0]["ref_functions"].append(-1)
        cache.import_refs()[0]["refs"].clear()
        cache.call_edges()[0]["caller"] = -1
        exported = cache.export()
        exported["functions"][0]["name"] = "corrupted"
        exported["string_refs"][0]["refs"][0]["to"] = -1
        exported["call_edges"].clear()

        self.assertEqual(cache.functions(), before["functions"])
        self.assertEqual(cache.string_refs(), before["string_refs"])
        self.assertEqual(cache.import_refs(), before["import_refs"])
        self.assertEqual(cache.call_edges(), before["call_edges"])
        self.assertEqual(cache.export(), before["export"])

    def test_decompile_reads_hand_out_detached_records(self) -> None:
        cache = IDACache(FakeCacheProvider())
        cache.refresh()
        first = cache.decompile(0x1000)
        first["pseudocode"] = "corrupted"

        self.assertNotEqual(cache.decompile(0x1000)["pseudocode"], "corrupted")


if __name__ == "__main__":
    unittest.main()
