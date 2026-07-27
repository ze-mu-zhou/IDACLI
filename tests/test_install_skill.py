"""Tests for scripts/install_skill.py source/destination conflict guards."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_install_skill() -> object:
    """Load scripts/install_skill.py as a module without packaging it."""
    spec = importlib.util.spec_from_file_location("install_skill", ROOT / "scripts" / "install_skill.py")
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load scripts/install_skill.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InstallSkillConflictTests(unittest.TestCase):
    """Guard against --target-root pointing at or inside the source skill."""

    def setUp(self) -> None:
        """Build a temporary repo layout with one codex skill source."""
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name)
        self.source = self.repo / "skills" / "codex" / "ida-cli"
        (self.source / "agents").mkdir(parents=True)
        (self.source / "SKILL.md").write_text("---\nname: ida-cli\n---\nbody\n", encoding="utf-8")
        (self.source / "agents" / "openai.yaml").write_text("policy: allow\n", encoding="utf-8")
        self.module = _load_install_skill()

    def _install(self, target_root: Path, *, force: bool) -> dict[str, str]:
        """Call _install_one with _repo_root patched to the temporary repo."""
        with mock.patch.object(self.module, "_repo_root", return_value=self.repo):
            return self.module._install_one("codex", target_root=target_root, force=force)

    def _assert_source_preserved(self) -> None:
        """Assert every source skill file still exists with its original content."""
        self.assertEqual(
            (self.source / "SKILL.md").read_text(encoding="utf-8"),
            "---\nname: ida-cli\n---\nbody\n",
        )
        self.assertEqual(
            (self.source / "agents" / "openai.yaml").read_text(encoding="utf-8"),
            "policy: allow\n",
        )

    def test_destination_equal_source_with_force_raises_and_preserves_source(self) -> None:
        with self.assertRaises(self.module.InstallError):
            self._install(self.source.parent, force=True)
        self._assert_source_preserved()

    def test_destination_inside_source_with_force_raises_and_preserves_source(self) -> None:
        with self.assertRaises(self.module.InstallError):
            self._install(self.source / "nested", force=True)
        self._assert_source_preserved()

    def test_unrelated_destination_with_force_overwrite_still_succeeds(self) -> None:
        target_root = self.repo / "target"
        stale = target_root / "ida-cli" / "stale.txt"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale\n", encoding="utf-8")

        result = self._install(target_root, force=True)

        self.assertEqual(result["destination"], str(target_root / "ida-cli"))
        self.assertTrue((target_root / "ida-cli" / "SKILL.md").is_file())
        self.assertTrue((target_root / "ida-cli" / "agents" / "openai.yaml").is_file())
        self.assertFalse(stale.exists())
        self._assert_source_preserved()


if __name__ == "__main__":
    unittest.main()
