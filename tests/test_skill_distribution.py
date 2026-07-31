"""Tests for distributed Codex, Kimi Code, Claude Code, and Reasonix skills."""

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
        claude = _frontmatter(ROOT / "skills" / "claude" / "ida-cli" / "SKILL.md")
        reasonix = _frontmatter(ROOT / "skills" / "reasonix" / "ida-cli" / "SKILL.md")

        self.assertEqual(codex["name"], "ida-cli")
        self.assertIn("Codex", codex["description"])
        self.assertEqual(kimi["name"], "ida-cli")
        self.assertIn("Kimi Code", kimi["description"])
        self.assertEqual(claude["name"], "ida-cli")
        self.assertIn("Claude Code", claude["description"])
        self.assertEqual(reasonix["name"], "ida-cli")
        self.assertIn("Reasonix", reasonix["description"])

    def test_all_skills_require_readiness_and_preserve_license_errors(self) -> None:
        for agent in ("codex", "kimi", "claude", "reasonix"):
            with self.subTest(agent=agent):
                text = (ROOT / "skills" / agent / "ida-cli" / "SKILL.md").read_text(encoding="utf-8")
                self.assertIn("ida-ai doctor", text)
                self.assertIn("ida-ai doctor --fix-license", text)
                self.assertIn("IdaLicenseNotAcceptedError", text)
                self.assertIn("AgentBridgeLicenseError", text)
                self.assertIn('license_accepted: true', text)
                self.assertIn("Never click the acceptance control for the user", text)

    def test_agent_install_guide_documents_github_install_and_clean_reinstall(self) -> None:
        text = (ROOT / "docs" / "AI_INSTALL.md").read_text(encoding="utf-8")

        self.assertIn("$skill-installer", text)
        self.assertIn("ze-mu-zhou/IDACLI", text)
        self.assertIn("skills/codex/ida-cli", text)
        self.assertIn("install-skill-from-github.py", text)
        self.assertIn("Do not remove the IDA-CLI development clone", text)
        self.assertIn("python scripts/install_skill.py claude --force", text)
        self.assertIn("~/.claude/skills/ida-cli", text)

    def test_readmes_do_not_claim_openai_agents_support(self) -> None:
        for name in ("README.md", "README_EN.md"):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertNotIn("OpenAI Agents", text)
                self.assertIn("Claude Code", text)

    def test_install_script_copies_all_skill_flavors(self) -> None:
        script = ROOT / "scripts" / "install_skill.py"
        with tempfile.TemporaryDirectory() as tmp:
            codex_root = Path(tmp) / "codex-skills"
            kimi_root = Path(tmp) / "kimi-skills"
            claude_root = Path(tmp) / "claude-skills"
            reasonix_root = Path(tmp) / "reasonix-skills"
            all_root = Path(tmp) / "all-skills"
            codex = _run_install(script, "codex", codex_root)
            kimi = _run_install(script, "kimi", kimi_root)
            claude = _run_install(script, "claude", claude_root)
            reasonix = _run_install(script, "reasonix", reasonix_root)
            installed = _run_install(script, "all", all_root)

            self.assertTrue((codex_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((codex_root / "ida-cli" / "agents" / "openai.yaml").is_file())
            self.assertTrue((kimi_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((claude_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((reasonix_root / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "codex" / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "kimi" / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "claude" / "ida-cli" / "SKILL.md").is_file())
            self.assertTrue((all_root / "reasonix" / "ida-cli" / "SKILL.md").is_file())
            self.assertEqual(codex["installed"][0]["agent"], "codex")
            self.assertEqual(kimi["installed"][0]["agent"], "kimi")
            self.assertEqual(claude["installed"][0]["agent"], "claude")
            self.assertEqual(reasonix["installed"][0]["agent"], "reasonix")
            self.assertEqual(
                [item["agent"] for item in installed["installed"]],
                ["codex", "kimi", "claude", "reasonix"],
            )


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
