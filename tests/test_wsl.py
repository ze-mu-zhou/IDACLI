"""Tests for pure WSL path-conversion fallbacks; no WSL installation required."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli import daemon
from ida_cli.wsl import _fallback_win_to_wsl, _fallback_wsl_to_win


class FallbackWslToWinTests(unittest.TestCase):
    """Cover /mnt path conversion without wslpath."""

    def test_converts_mnt_drive_path(self) -> None:
        self.assertEqual(_fallback_wsl_to_win("/mnt/d/work/target.i64"), "D:\\work\\target.i64")

    def test_preserves_spaces_in_components(self) -> None:
        self.assertEqual(
            _fallback_wsl_to_win("/mnt/c/Program Files/IDA Pro/ida.exe"),
            "C:\\Program Files\\IDA Pro\\ida.exe",
        )

    def test_trailing_slash_is_normalized(self) -> None:
        self.assertEqual(_fallback_wsl_to_win("/mnt/d/work/"), "D:\\work")

    def test_drive_root_converts_to_drive_letter_root(self) -> None:
        self.assertEqual(_fallback_wsl_to_win("/mnt/d"), "D:\\")
        self.assertEqual(_fallback_wsl_to_win("/mnt/e/"), "E:\\")

    def test_non_mnt_paths_pass_through(self) -> None:
        self.assertEqual(_fallback_wsl_to_win("/home/user/target.i64"), "/home/user/target.i64")
        self.assertEqual(_fallback_wsl_to_win("relative/target.i64"), "relative/target.i64")
        self.assertEqual(_fallback_wsl_to_win("/mnt"), "/mnt")

    def test_multi_letter_mnt_names_pass_through(self) -> None:
        # /mnt/data is not /mnt/<drive>: fabricating "D:\ta\..." corrupts the
        # path and can collide with a real /mnt/d/ta/... spelling.
        self.assertEqual(_fallback_wsl_to_win("/mnt/data/a"), "/mnt/data/a")
        self.assertEqual(_fallback_wsl_to_win("/mnt/data/a.i64"), "/mnt/data/a.i64")
        self.assertEqual(_fallback_wsl_to_win("/mnt/storage/x/a.i64"), "/mnt/storage/x/a.i64")


class FallbackWinToWslTests(unittest.TestCase):
    """Cover drive-letter path conversion without wslpath."""

    def test_converts_drive_letter_path(self) -> None:
        self.assertEqual(_fallback_win_to_wsl("D:\\work\\target.i64"), "/mnt/d/work/target.i64")

    def test_preserves_spaces_in_components(self) -> None:
        self.assertEqual(
            _fallback_win_to_wsl("C:\\Program Files\\IDA Pro\\ida.exe"),
            "/mnt/c/Program Files/IDA Pro/ida.exe",
        )

    def test_accepts_forward_slash_tail(self) -> None:
        self.assertEqual(_fallback_win_to_wsl("D:/work/target.i64"), "/mnt/d/work/target.i64")

    def test_trailing_backslash_keeps_trailing_slash(self) -> None:
        self.assertEqual(_fallback_win_to_wsl("D:\\work\\"), "/mnt/d/work/")

    def test_drive_root_converts_to_mnt_root(self) -> None:
        self.assertEqual(_fallback_win_to_wsl("D:\\"), "/mnt/d/")

    def test_non_drive_paths_pass_through(self) -> None:
        self.assertEqual(_fallback_win_to_wsl("\\\\wsl$\\Debian\\tmp\\x"), "\\\\wsl$\\Debian\\tmp\\x")
        self.assertEqual(_fallback_win_to_wsl("/mnt/d/x"), "/mnt/d/x")


class FallbackRoundTripTests(unittest.TestCase):
    """Round-trip paths through both fallbacks."""

    def test_wsl_to_win_round_trip(self) -> None:
        original = "/mnt/d/work/target.i64"
        self.assertEqual(_fallback_win_to_wsl(_fallback_wsl_to_win(original)), original)

    def test_win_to_wsl_round_trip(self) -> None:
        original = "D:\\work\\target.i64"
        self.assertEqual(_fallback_wsl_to_win(_fallback_win_to_wsl(original)), original)

    def test_round_trip_with_spaces(self) -> None:
        original = "/mnt/c/Program Files/IDA Pro/ida.exe"
        self.assertEqual(_fallback_win_to_wsl(_fallback_wsl_to_win(original)), original)


class NormalizeTargetPathTests(unittest.TestCase):
    """Cover daemon-side /mnt normalization used for target hashing."""

    def test_normalizes_mnt_path_to_windows_form(self) -> None:
        self.assertEqual(daemon._normalize_target_path("/mnt/d/x"), "D:\\x")
        self.assertEqual(
            daemon._normalize_target_path("/mnt/d/work/target.i64"),
            "D:\\work\\target.i64",
        )

    def test_windows_path_passes_through(self) -> None:
        self.assertEqual(
            daemon._normalize_target_path("D:\\work\\target.i64"),
            "D:\\work\\target.i64",
        )

    def test_non_mnt_linux_path_resolves_to_absolute(self) -> None:
        # Absolute POSIX paths resolve to themselves on POSIX hosts; on
        # Windows they resolve against the current drive. Either way the
        # result is absolute and keeps the original tail.
        result = daemon._normalize_target_path("/home/user/x")
        self.assertTrue(os.path.isabs(result))
        self.assertTrue(result.replace("\\", "/").endswith("/home/user/x"))

    def test_short_mnt_prefix_resolves_to_absolute(self) -> None:
        # "/mnt/" is not a valid /mnt/<drive> WSL path, so it resolves like
        # any other local path instead of passing through.
        result = daemon._normalize_target_path("/mnt/")
        self.assertTrue(os.path.isabs(result))
        self.assertTrue(result.replace("\\", "/").endswith("/mnt"))

    def test_single_letter_mnt_root_maps_to_drive_root(self) -> None:
        self.assertEqual(daemon._normalize_target_path("/mnt/d"), "D:\\")
        self.assertEqual(daemon._normalize_target_path("/mnt/E"), "E:\\")

    def test_multi_letter_mnt_names_fall_through_to_resolve(self) -> None:
        # Only ^/mnt/<letter>($|/) is a drive mapping; longer names must not
        # fabricate drive letters ("/mnt/data/..." is not "D:\ta\...").
        for raw, fabricated in (
            ("/mnt/data/a.i64", "D:\\ta\\a.i64"),
            ("/mnt/storage/x/a.i64", "S:\\orage\\x\\a.i64"),
        ):
            with self.subTest(raw=raw):
                result = daemon._normalize_target_path(raw)
                self.assertNotEqual(result, fabricated)
                self.assertTrue(os.path.isabs(result))
                self.assertTrue(result.replace("\\", "/").endswith(raw))

    def test_exact_mnt_drive_path_maps_to_windows_form(self) -> None:
        self.assertEqual(
            daemon._normalize_target_path("/mnt/d/pwn/a.i64"),
            "D:\\pwn\\a.i64",
        )

    def test_normalizes_spaces(self) -> None:
        self.assertEqual(
            daemon._normalize_target_path("/mnt/c/Program Files/ida.exe"),
            "C:\\Program Files\\ida.exe",
        )


if __name__ == "__main__":
    unittest.main()
