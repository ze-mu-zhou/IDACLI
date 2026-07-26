"""Tests for GitHub-distributed Codex and Kimi Code skills."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SkillDistributionTests(unittest.TestCase):
    """Validate that repo skills are installable without external tooling."""

    def test_skill_frontmatter_is_valid(self) -> None:
        codex = _frontmatter(ROOT / "skills" / "codex" / "ida-cli" / "SKILL.md")
        kimi = _frontmatter(ROOT / "skills" / "kimi" / "ida-cli" / "SKILL.md")

        self.assertEqual(codex["name"], "ida-cli")
        self.assertIn("Codex", codex["description"])
        self.assertEqual(kimi["name"], "ida-cli")
        self.assertIn("Kimi Code", kimi["description"])

    def test_install_script_copies_both_skill_flavors(self) -> None:
        script = ROOT / "scripts" / "install_skill.py"
        with tempfile.TemporaryDirectory() as tmp:
            codex_root = Path(tmp) / "codex-skills"
            kimi_root = Path(tmp) / "kimi-skills"
            all_root = Path(tmp) / "all-skills"
            codex = _run_install(script, "codex", codex_root)
            kimi = _run_install(script, "kimi", kimi_root)
            both = _run_install(script, "all", all_root)

            self.assertTrue((codex_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((codex_root / "ida-cli" / "agents" / "openai.yaml").is_file())
            self.assertTrue((kimi_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "codex" / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "kimi" / "ida-cli" / "SKILL.md").is_file())
            self.assertEqual(codex["installed"][0]["agent"], "codex")
            self.assertEqual(kimi["installed"][0]["agent"], "kimi")
            self.assertEqual([item["agent"] for item in both["installed"]], ["codex", "kimi"])


def _run_install(script: Path, agent: str, root: Path) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-B", str(script), agent, "--target-root", str(root), "--force"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise AssertionError(f"missing frontmatter start: {path}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise AssertionError(f"missing frontmatter end: {path}")
    result: dict[str, object] = {}
    current_list: str | None = None
    for line in text[4:end].splitlines():
        if line.startswith("  - ") and current_list is not None:
            cast = result[current_list]
            if not isinstance(cast, list):
                raise AssertionError(f"frontmatter list target is not a list: {path}")
            cast.append(line[4:])
            continue
        current_list = None
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key] = value
        elif line.endswith(":"):
            current_list = line[:-1]
            result[current_list] = []
        elif line.strip():
            raise AssertionError(f"unsupported frontmatter line {line!r}: {path}")
    if not isinstance(result.get("description"), str) or not result["description"]:
        raise AssertionError(f"invalid description: {path}")
    return result


if __name__ == "__main__":
    unittest.main()
