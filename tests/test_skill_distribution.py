"""Tests for GitHub-distributed Codex and Claude Code skills."""

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

    def test_codex_and_claude_skill_frontmatter_is_valid(self) -> None:
        codex = _frontmatter(ROOT / "skills" / "codex" / "ida-cli" / "SKILL.md")
        claude = _frontmatter(ROOT / "skills" / "claude" / "ida-cli" / "SKILL.md")
        project_claude = _frontmatter(ROOT / ".claude" / "skills" / "ida-cli" / "SKILL.md")

        self.assertEqual(codex["name"], "ida-cli")
        self.assertIn("Codex", codex["description"])
        self.assertEqual(claude["name"], "ida-cli")
        self.assertIn("Claude Code", claude["description"])
        self.assertIn("allowed-tools", claude)
        self.assertEqual(claude, project_claude)

    def test_install_script_copies_both_skill_flavors(self) -> None:
        script = ROOT / "scripts" / "install_skill.py"
        with tempfile.TemporaryDirectory() as tmp:
            codex_root = Path(tmp) / "codex-skills"
            claude_root = Path(tmp) / "claude-skills"
            all_root = Path(tmp) / "all-skills"
            codex = _run_install(script, "codex", codex_root)
            claude = _run_install(script, "claude", claude_root)
            both = _run_install(script, "all", all_root)

            self.assertTrue((codex_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((codex_root / "ida-cli" / "agents" / "openai.yaml").is_file())
            self.assertTrue((claude_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "codex" / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "claude" / "ida-cli" / "SKILL.md").is_file())
            self.assertEqual(codex["installed"][0]["agent"], "codex")
            self.assertEqual(claude["installed"][0]["agent"], "claude")
            self.assertEqual([item["agent"] for item in both["installed"]], ["codex", "claude"])


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
