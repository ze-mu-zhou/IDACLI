"""Tests for the IDA-optional AI helper layer."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_cli import ai_helpers
from ida_cli.ai_helpers import AIHelperError, AIHelpers


BADADDR = (1 << 64) - 1


class FakeFunction:
    """Small function object shaped like ida_funcs.func_t."""

    def __init__(self, start_ea: int = 0x1000, end_ea: int = 0x1004) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea


class FakeSegment:
    """Small segment object shaped like ida_segment.segment_t."""

    start_ea = 0x1000
    end_ea = 0x4000
    perm = 5
    bitness = 2


class FakeBlock:
    """Small FlowChart block with deterministic successors."""

    def __init__(self, start_ea: int, end_ea: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea
        self._successors: list[FakeBlock] = []

    def succs(self) -> list[FakeBlock]:
        return list(self._successors)


class FakeXref:
    """Small xref object shaped like IDAPython xref records."""

    def __init__(self, frm: int, to: int) -> None:
        self.frm = frm
        self.to = to
        self.type = 17
        self.iscode = True


class FakeString:
    """Small string object shaped like idautils.Strings entries."""

    def __init__(self, ea: int = 0x3000, value: str = "hello") -> None:
        self.ea = ea
        self.length = len(value)
        self.type = 0
        self._value = value

    def __str__(self) -> str:
        return self._value


class FakeCfunc:
    """Small Hex-Rays result object whose string form is pseudocode."""

    def __str__(self) -> str:
        return "int start(void) { return 0; }"


def fake_modules(*, with_decompiler: bool = True) -> dict[str, object]:
    """Build deterministic IDAPython-shaped modules for helper tests."""

    def get_func(ea: int) -> FakeFunction | None:
        if 0x1000 <= ea < 0x1004:
            return FakeFunction(0x1000, 0x1004)
        if 0x1010 <= ea < 0x1014:
            return FakeFunction(0x1010, 0x1014)
        if 0x2000 <= ea < 0x2004:
            return FakeFunction(0x2000, 0x2004)
        return None

    def get_func_name(ea: int) -> str | None:
        return {0x1000: "start", 0x1010: "caller", 0x2000: "puts"}.get(ea)

    def get_name_ea_simple(name: str) -> int:
        return {"start": 0x1000, "caller": 0x1010, "puts": 0x2000}.get(name, BADADDR)

    def enum_import_names(_index: int, callback: object) -> bool:
        callback(0x2000, "puts", 7)
        return True

    block_a = FakeBlock(0x1000, 0x1002)
    block_b = FakeBlock(0x1002, 0x1004)
    block_a._successors.append(block_b)

    modules: dict[str, object] = {
        "idaapi": SimpleNamespace(BADADDR=BADADDR),
        "idautils": SimpleNamespace(
            Functions=lambda: [0x1000],
            FuncItems=lambda _ea: [0x1000, 0x1001],
            Names=lambda: [(0x1000, "start"), (0x1010, "caller"), (0x2000, "puts")],
            Segments=lambda: [0x1000],
            Entries=lambda: [(0, 1, 0x1000, "start")],
            XrefsTo=lambda _ea: [FakeXref(0x1010, 0x1000)],
            XrefsFrom=lambda _ea: [FakeXref(0x1000, 0x2000)],
            Strings=lambda: [FakeString()],
        ),
        "ida_funcs": SimpleNamespace(get_func=get_func, get_func_name=get_func_name),
        "ida_segment": SimpleNamespace(
            getseg=lambda _ea: FakeSegment(),
            get_segm_name=lambda _seg: ".text",
            get_segm_class=lambda _seg: "CODE",
        ),
        "ida_gdl": SimpleNamespace(FlowChart=lambda _func: [block_a, block_b]),
        "idc": SimpleNamespace(
            BADADDR=BADADDR,
            get_name_ea_simple=get_name_ea_simple,
            get_type=lambda ea: "int start(void)" if ea == 0x1000 else None,
            get_operand_value=lambda _ea, index: 0x40 + index,
            demangle_name=lambda name, _flags: f"demangled::{name}",
            generate_disasm_line=lambda ea, _flags: {0x1000: "push rbp", 0x1001: "ret"}.get(ea, "nop"),
        ),
        "ida_bytes": SimpleNamespace(
            get_bytes=lambda _ea, size: bytes([0x90] * size),
            get_cmt=lambda _ea, repeatable: "repeat" if repeatable else "plain",
            get_item_size=lambda _ea: 1,
        ),
        "ida_typeinf": SimpleNamespace(print_type=lambda ea, _flags: "int start(void)" if ea == 0x1000 else None),
        "ida_nalt": SimpleNamespace(
            get_import_module_qty=lambda: 1,
            get_import_module_name=lambda _index: "msvcrt",
            enum_import_names=enum_import_names,
        ),
    }
    if with_decompiler:
        modules["ida_hexrays"] = SimpleNamespace(init_hexrays_plugin=lambda: True, decompile=lambda _ea: FakeCfunc())
    return modules


class AIHelpersTests(unittest.TestCase):
    """Exercise helper behavior without requiring IDA to be installed."""

    def test_write_artifact_without_ida_writes_json_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = AIHelpers(tmp, auto_import=False)
            meta = helper.write_artifact("facts", {"answer": 42})
            artifact = Path(meta["artifact"])
            payload = artifact.read_bytes()

        self.assertEqual(meta["format"], "json")
        self.assertEqual(meta["count"], 1)
        self.assertEqual(meta["bytes"], len(payload))
        self.assertEqual(meta["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(json.loads(payload), {"answer": 42})

    def test_write_artifact_rejects_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = AIHelpers(tmp, auto_import=False)
            with self.assertRaises(AIHelperError):
                helper.write_artifact("../escape.json", {"bad": True})

    def test_get_ea_accepts_integer_without_ida_and_rejects_name(self) -> None:
        helper = AIHelpers(auto_import=False)
        self.assertEqual(helper.get_ea(0x401000), 0x401000)
        self.assertEqual(ai_helpers.get_ea(0x401000), 0x401000)
        with self.assertRaises(AIHelperError):
            helper.get_ea("start")

    def test_fake_ida_methods_return_json_compatible_records(self) -> None:
        helper = AIHelpers(modules=fake_modules(), auto_import=False)

        self.assertEqual(helper.get_ea("start"), 0x1000)
        self.assertEqual(helper.functions()[0]["name"], "start")
        self.assertEqual(helper.function(0x1001)["size"], 4)
        self.assertEqual(helper.decompile("start")["pseudocode"], "int start(void) { return 0; }")
        self.assertEqual(helper.disasm("start", 2)[0]["line"], "push rbp")
        self.assertEqual(helper.xrefs("start")["from"][0]["to"], 0x2000)
        self.assertEqual(helper.xrefs_to("start")[0]["frm"], 0x1010)
        self.assertEqual(helper.xrefs_from("start")[0]["to"], 0x2000)
        self.assertEqual(helper.strings(1)[0]["value"], "hello")
        self.assertEqual(helper.imports()[0]["name"], "puts")
        self.assertEqual(helper.segments()[0]["name"], ".text")
        self.assertEqual(helper.entries()[0]["ordinal"], 1)
        self.assertEqual(helper.exports()[0]["name"], "start")
        self.assertEqual(helper.names()[0]["name"], "start")
        self.assertEqual(helper.bytes_hex("start", 2)["hex"], "9090")
        self.assertEqual(helper.bytes_at("start", 2)["bytes"], [0x90, 0x90])
        self.assertEqual(helper.item_size("start")["size"], 1)
        self.assertEqual(helper.comments("start")["repeatable"], "repeat")
        self.assertEqual(helper.type_at("start")["type"], "int start(void)")
        self.assertEqual(helper.operand_value("start", 1)["value"], 0x41)
        self.assertEqual(helper.function_bounds("start")["end_ea"], 0x1004)
        self.assertEqual(helper.callers("start")[0]["function"]["name"], "caller")
        self.assertEqual(helper.callees("start")[0]["function"]["name"], "puts")
        self.assertEqual(helper.basic_blocks("start")[0]["start_ea"], 0x1000)
        self.assertEqual(helper.cfg("start")["edges"][0]["dst_ea"], 0x1002)
        self.assertEqual(helper.demangle("?start@@YAHXZ")["demangled"], "demangled::?start@@YAHXZ")

    def test_decompile_fails_fast_without_disassembly_fallback(self) -> None:
        helper = AIHelpers(modules=fake_modules(with_decompiler=False), auto_import=False)
        with self.assertRaisesRegex(AIHelperError, "fallback is forbidden"):
            helper.decompile("start")

    def test_more_ida_helpers_fail_fast_on_unbounded_inputs(self) -> None:
        helper = AIHelpers(modules=fake_modules(), auto_import=False)
        with self.assertRaisesRegex(AIHelperError, "size must be <="):
            helper.bytes_hex("start", (1 << 20) + 1)
        with self.assertRaisesRegex(AIHelperError, "index must be <="):
            helper.operand_value("start", 8)

    def test_context_pack_decompiles_only_when_explicitly_requested(self) -> None:
        modules = fake_modules()
        modules["ida_hexrays"] = SimpleNamespace(decompile=lambda _ea: (_ for _ in ()).throw(RuntimeError("boom")))
        helper = AIHelpers(modules=modules, auto_import=False)

        pack = helper.context_pack("start", disasm_limit=1)
        self.assertNotIn("decompile", pack)
        with self.assertRaisesRegex(AIHelperError, "decompile failed"):
            helper.context_pack("start", include_decompile=True)

    def test_focus_summary_and_inventory_export_keep_large_data_in_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = AIHelpers(tmp, modules=fake_modules(), auto_import=False)

            focused = helper.focus("start", disasm_limit=1)
            summary = helper.inventory_summary(function_limit=1, string_limit=1)
            exported = helper.export_inventory("triage", string_limit=1)

            self.assertEqual(focused["targets"]["start"]["disasm"][0]["line"], "push rbp")
            self.assertEqual(summary["counts"]["functions"], 1)
            self.assertEqual(len(summary["functions"]), 1)
            for metadata in exported.values():
                self.assertTrue(Path(metadata["artifact"]).is_file())

    def test_pwn_overview_collects_dangerous_imports_and_shell_clues(self) -> None:
        modules = fake_modules()

        def enum_import_names(_index: int, callback: object) -> bool:
            callback(0x2000, "system@@GLIBC_2.2.5", 1)
            callback(0x2010, "gets@@GLIBC_2.2.5", 2)
            callback(0x2020, "__stack_chk_fail@@GLIBC_2.4", 3)
            return True

        modules["ida_nalt"] = SimpleNamespace(
            get_import_module_qty=lambda: 1,
            get_import_module_name=lambda _index: "libc.so.6",
            enum_import_names=enum_import_names,
        )
        modules["idautils"].Names = lambda: [(0x1000, "start"), (0x401229, "backdoor")]
        modules["idautils"].Strings = lambda: [FakeString(0x3000, "/bin/sh"), FakeString(0x3010, "flag.txt")]
        helper = AIHelpers(modules=modules, auto_import=False)

        overview = helper.pwn_overview()

        self.assertTrue(overview["mitigation_hints"]["stack_canary_import"])
        self.assertIn("system", {item["name"] for item in overview["dangerous_imports"]})
        self.assertIn("backdoor", {item["name"] for item in overview["interesting_symbols"]})
        self.assertIn("/bin/sh", {item["value"] for item in overview["string_hits"]})

    def test_mutation_methods_are_available_on_ai_helper_and_mark_cache_stale(self) -> None:
        state = {
            "bytes": {0x1000: 0x90},
            "comments": {},
            "names": {0x1000: "start"},
            "saved": [],
            "types": {0x1000: "int old(void);"},
        }

        def get_name(ea: int) -> str | None:
            return state["names"].get(ea)

        def get_name_ea(_badaddr: int, name: str) -> int:
            for ea, current in state["names"].items():
                if current == name:
                    return ea
            return BADADDR

        modules = {
            "ida_idaapi": SimpleNamespace(BADADDR=BADADDR),
            "ida_name": SimpleNamespace(
                get_name=get_name,
                get_name_ea=get_name_ea,
                set_name=lambda ea, name, _flags: state["names"].__setitem__(ea, name) is None or True,
            ),
            "ida_bytes": SimpleNamespace(
                get_db_byte=lambda ea: state["bytes"].get(ea, -1),
                get_cmt=lambda ea, repeatable: state["comments"].get((ea, repeatable)),
                patch_byte=lambda ea, value: state["bytes"].__setitem__(ea, value) is None or True,
                set_cmt=lambda ea, text, repeatable: state["comments"].__setitem__((ea, repeatable), text) is None or True,
            ),
            "ida_typeinf": SimpleNamespace(
                apply_cdecl=lambda _til, ea, decl, _flags: state["types"].__setitem__(ea, decl) is None or True,
                get_idati=lambda: "til",
                print_type=lambda ea, _flags: state["types"].get(ea),
            ),
            "ida_loader": SimpleNamespace(save_database=lambda path, flags: state["saved"].append((path, flags)) is None or True),
        }
        helper = AIHelpers(modules=modules, auto_import=False)

        renamed = helper.rename("start", "better_start")
        commented = helper.set_comment(0x1000, "note", repeatable=True)
        typed = helper.apply_type(0x1000, "int better_start(void);")
        patched = helper.patch_byte(0x1000, 0xCC)
        saved = helper.save_database("out.i64")

        self.assertEqual(renamed["changed_names"][0]["after"], "better_start")
        self.assertEqual(commented["after"]["comment"], "note")
        self.assertEqual(typed["after"]["type"], "int better_start(void);")
        self.assertEqual(patched["after"]["bytes"], "cc")
        self.assertEqual(saved["kind"], "save_database")
        self.assertTrue(helper.cache_status()["stale"])
        self.assertIn("patched", helper.cache_status()["stale_reason"])

    def test_cache_methods_are_available_on_ai_helper_and_export_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = AIHelpers(tmp, modules=fake_modules(), auto_import=False)

            status = helper.refresh_cache()
            functions = helper.cached_functions()
            decompiled = helper.cached_decompile("start")
            exported = helper.export_cache("cache/index.json")
            saved = helper.save_cache(Path(tmp) / "persistent-cache.json")
            helper.mark_cache_stale("test reload")
            loaded = helper.load_cache(saved["path"])
            artifact = Path(exported["artifact"]["artifact"])

            self.assertFalse(status["stale"])
            self.assertEqual(functions[0]["name"], "start")
            self.assertIn("return 0", decompiled["pseudocode"])
            self.assertFalse(loaded["status"]["stale"])
            self.assertTrue(artifact.is_file())
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))["schema"], "ida-cli-cache-index-v1")

    def test_change_merge_is_available_on_ai_helper(self) -> None:
        helper = AIHelpers(auto_import=False)
        left = {"kind": "rename", "target": {"ea": 1}, "after": {"name": "a"}, "changed_addresses": [1]}
        right = {"kind": "rename", "target": {"ea": 1}, "after": {"name": "b"}, "changed_addresses": [1]}

        merged = helper.merge_change_sets(({"branch": "left", "changes": [left]}, {"branch": "right", "changes": [right]}))

        self.assertFalse(merged["ok"])
        self.assertEqual(merged["conflicts"][0]["resource"], ["name", 1])


if __name__ == "__main__":
    unittest.main()
