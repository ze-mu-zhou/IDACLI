"""Tests for local database mutation helpers."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli.mutations import DatabaseMutations, MutationError


BADADDR = (1 << 64) - 1


class FakeIdaDatabase:
    """Mutable fake shaped like the IDAPython modules used by mutations."""

    def __init__(self) -> None:
        # Keep fake state tiny and deterministic; when extending this, obey exact IDA API return semantics.
        self.names = {0x1000: "start"}
        self.comments = {(0x1000, False): "old local", (0x1000, True): "old repeatable"}
        self.types = {0x1000: "int old(void);"}
        self.bytes = {0x2000: 0x90, 0x2001: 0x00, 0x2002: 0xCC}
        self.saved: list[tuple[str | None, int]] = []
        self.fail_name = False
        self.fail_type = False
        self.fail_patch = False
        self.fail_save = False

    def modules(self) -> dict[str, object]:
        """Return injected IDAPython-shaped modules for helper tests."""

        return {
            "ida_idaapi": SimpleNamespace(BADADDR=BADADDR),
            "ida_name": SimpleNamespace(
                get_name=self.get_name,
                get_name_ea=self.get_name_ea,
                set_name=self.set_name,
            ),
            "ida_bytes": SimpleNamespace(
                get_db_byte=self.get_db_byte,
                get_cmt=self.get_cmt,
                patch_byte=self.patch_byte,
                set_cmt=self.set_cmt,
            ),
            "ida_typeinf": SimpleNamespace(
                apply_cdecl=self.apply_cdecl,
                get_idati=lambda: "local-til",
                print_type=self.print_type,
            ),
            "ida_loader": SimpleNamespace(save_database=self.save_database),
        }

    def get_name(self, ea: int) -> str | None:
        """Return the fake name at an address."""

        return self.names.get(ea)

    def get_name_ea(self, _badaddr: int, name: str) -> int:
        """Resolve a fake name exactly like ida_name.get_name_ea."""

        for ea, current in self.names.items():
            if current == name:
                return ea
        return BADADDR

    def set_name(self, ea: int, name: str, _flags: int) -> bool:
        """Set or reject a fake IDA name."""

        if self.fail_name:
            return False
        self.names[ea] = name
        return True

    def get_cmt(self, ea: int, repeatable: bool) -> str | None:
        """Return a fake repeatable or non-repeatable comment."""

        return self.comments.get((ea, repeatable))

    def set_cmt(self, ea: int, comment: str, repeatable: bool) -> bool:
        """Set a fake repeatable or non-repeatable comment."""

        self.comments[(ea, repeatable)] = comment
        return True

    def print_type(self, ea: int, _flags: int) -> str | None:
        """Return the fake type string for an address."""

        return self.types.get(ea)

    def apply_cdecl(self, til: str, ea: int, declaration: str, _flags: int) -> bool:
        """Apply or reject a fake C declaration."""

        if til != "local-til" or self.fail_type:
            return False
        self.types[ea] = declaration
        return True

    def get_db_byte(self, ea: int) -> int:
        """Return a fake byte value or an invalid sentinel."""

        return self.bytes.get(ea, -1)

    def patch_byte(self, ea: int, value: int) -> bool:
        """Patch or reject one fake byte."""

        if self.fail_patch:
            return False
        self.bytes[ea] = value
        return True

    def save_database(self, path: str | None, flags: int) -> bool:
        """Record or reject one explicit fake database save."""

        if self.fail_save:
            return False
        self.saved.append((path, flags))
        return True


def helper_for(fake: FakeIdaDatabase) -> DatabaseMutations:
    """Create a mutation helper with fake modules and no imports."""

    return DatabaseMutations(modules=fake.modules(), auto_import=False)


class MutationTests(unittest.TestCase):
    """Exercise mutation helpers without requiring IDA to be installed."""

    def test_rename_records_proposed_and_applied_exact_names(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        proposed = helper.propose_rename("start", "better_start", flags=4)
        applied = helper.rename("start", "better_start", flags=4)

        self.assertFalse(proposed["applied"])
        self.assertEqual(proposed["changed_addresses"], [0x1000])
        self.assertEqual(proposed["changed_names"][0]["before"], "start")
        self.assertTrue(applied["applied"])
        self.assertEqual(applied["changed_names"], [{"ea": 0x1000, "before": "start", "after": "better_start"}])
        self.assertEqual(fake.names[0x1000], "better_start")
        json.dumps(applied, allow_nan=False, sort_keys=True)

    def test_comments_support_repeatable_and_nonrepeatable_records(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        local = helper.set_nonrepeatable_comment(0x1000, "local note")
        repeatable = helper.set_repeatable_comment(0x1000, "repeatable note")

        self.assertEqual(local["target"], {"ea": 0x1000, "repeatable": False})
        self.assertEqual(repeatable["target"], {"ea": 0x1000, "repeatable": True})
        self.assertEqual(fake.comments[(0x1000, False)], "local note")
        self.assertEqual(fake.comments[(0x1000, True)], "repeatable note")
        json.dumps([local, repeatable], allow_nan=False, sort_keys=True)

    def test_apply_type_reports_requested_and_actual_type(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        proposed = helper.propose_type(0x1000, "int start(int argc);")
        applied = helper.apply_type(0x1000, "int start(int argc);")

        self.assertEqual(proposed["status"], "proposed")
        self.assertEqual(applied["before"]["type"], "int old(void);")
        self.assertEqual(applied["after"], {"requested_type": "int start(int argc);", "type": "int start(int argc);"})
        self.assertEqual(applied["changed_addresses"], [0x1000])
        json.dumps(applied, allow_nan=False, sort_keys=True)

    def test_patch_bytes_reports_only_exact_changed_addresses(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        proposed = helper.propose_patch_bytes("0x2000", "90 cc")
        applied = helper.patch_bytes("0x2000", b"\x90\xcc")

        self.assertFalse(proposed["applied"])
        self.assertEqual(proposed["before"]["bytes"], "9000")
        self.assertEqual(applied["after"]["bytes"], "90cc")
        self.assertEqual(applied["changed_addresses"], [0x2001])
        self.assertEqual(fake.bytes[0x2000], 0x90)
        self.assertEqual(fake.bytes[0x2001], 0xCC)
        json.dumps(applied, allow_nan=False, sort_keys=True)

    def test_patch_byte_uses_same_record_format(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        applied = helper.patch_byte(0x2002, 0x90)

        self.assertEqual(applied["kind"], "patch_bytes")
        self.assertEqual(applied["target"]["length"], 1)
        self.assertEqual(applied["changed_addresses"], [0x2002])

    def test_save_database_is_explicit_and_json_compatible(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        proposed = helper.propose_save_database("copy.i64", flags=2)
        applied = helper.save("copy.i64", flags=2)

        self.assertEqual(proposed["status"], "proposed")
        self.assertEqual(applied["target"], {"path": "copy.i64"})
        self.assertEqual(applied["metadata"], {"api": "ida_loader.save_database", "flags": 2})
        self.assertEqual(fake.saved, [("copy.i64", 2)])
        json.dumps(applied, allow_nan=False, sort_keys=True)

    def test_helpers_do_not_write_stdout(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)
        captured = io.StringIO()

        with contextlib.redirect_stdout(captured):
            helper.rename("start", "quiet_start")
            helper.set_comment(0x1000, "quiet")
            helper.patch_bytes(0x2000, "90cc")

        self.assertEqual(captured.getvalue(), "")

    def test_missing_modules_and_failed_apis_raise_fast(self) -> None:
        with self.assertRaisesRegex(MutationError, "ida_idaapi"):
            DatabaseMutations(modules={}, auto_import=False).rename(0x1000, "x")

        fake = FakeIdaDatabase()
        fake.fail_name = True
        with self.assertRaisesRegex(MutationError, "ida_name.set_name"):
            helper_for(fake).rename("start", "rejected")

        fake = FakeIdaDatabase()
        fake.fail_type = True
        with self.assertRaisesRegex(MutationError, "ida_typeinf.apply_cdecl"):
            helper_for(fake).apply_type(0x1000, "int rejected(void);")

        fake = FakeIdaDatabase()
        fake.fail_patch = True
        with self.assertRaisesRegex(MutationError, "ida_bytes.patch_byte"):
            helper_for(fake).patch_bytes(0x2000, "91")

        fake = FakeIdaDatabase()
        fake.fail_save = True
        with self.assertRaisesRegex(MutationError, "ida_loader.save_database"):
            helper_for(fake).save_database()

    def test_invalid_inputs_are_rejected_without_mutation(self) -> None:
        fake = FakeIdaDatabase()
        helper = helper_for(fake)

        with self.assertRaises(MutationError):
            helper.rename(True, "bad")
        with self.assertRaises(MutationError):
            helper.patch_bytes(0x2000, "abc")
        with self.assertRaises(MutationError):
            helper.patch_byte(0x2000, 256)
        self.assertEqual(fake.names[0x1000], "start")
        self.assertEqual(fake.bytes[0x2000], 0x90)


if __name__ == "__main__":
    unittest.main()
