#!/usr/bin/env python3
import importlib.util
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

script_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../.contrib/package_plugin.py")
)
spec = importlib.util.spec_from_file_location("package_plugin", script_path)
package_plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_plugin)

build_package = package_plugin.build_package


class TestPackagePlugin(unittest.TestCase):
    def test_build_package_contents(self):
        repo_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            tar_path, zip_path = build_package(repo_root, out_dir)

            self.assertTrue(tar_path.exists())
            self.assertTrue(zip_path.exists())
            self.assertTrue((out_dir / "auto-permissions.tar.gz").exists())
            self.assertTrue((out_dir / "auto-permissions.zip").exists())

            with tarfile.open(tar_path, "r:gz") as tar:
                names = tar.getnames()

                # Required release files
                self.assertIn("auto-permissions/plugin.json", names)
                self.assertIn("auto-permissions/hooks.json", names)
                self.assertIn("auto-permissions/LICENSE", names)
                self.assertIn("auto-permissions/README.md", names)
                self.assertIn("auto-permissions/hooks/auto_approve_gate.py", names)
                self.assertIn("auto-permissions/rules/auto_permissions.md", names)
                self.assertIn("auto-permissions/skills/auto-permissions-configure/SKILL.md", names)

                # Development files that MUST NOT be present
                for name in names:
                    self.assertNotIn("tests/", name)
                    self.assertNotIn("docs/", name)
                    self.assertNotIn(".github", name)
                    self.assertNotIn(".contrib", name)
                    self.assertNotIn(".pre-commit", name)
                    self.assertNotIn("pyproject.toml", name)
                    self.assertNotIn("uv.lock", name)
                    self.assertNotIn(".venv", name)
                    self.assertNotIn("__pycache__", name)

    def test_rules_and_skills_yaml_frontmatter(self):
        repo_root = Path(__file__).resolve().parent.parent

        # 1. Validate rules/*.md
        rules_dir = repo_root / "rules"
        rule_files = list(rules_dir.glob("*.md"))
        self.assertGreater(len(rule_files), 0, "No rule markdown files found")

        for rule_file in rule_files:
            content = rule_file.read_text(encoding="utf-8")
            self.assertTrue(
                content.startswith("---\n"),
                f"Rule file {rule_file.name} missing opening YAML frontmatter delimiter '---'",
            )
            parts = content.split("---\n", 2)
            self.assertGreaterEqual(
                len(parts),
                3,
                f"Rule file {rule_file.name} missing closing YAML frontmatter delimiter '---'",
            )
            fm = parts[1]
            self.assertIn("name:", fm, f"Rule file {rule_file.name} missing 'name' in frontmatter")
            self.assertIn(
                "description:",
                fm,
                f"Rule file {rule_file.name} missing 'description' in frontmatter",
            )
            self.assertIn(
                "always_on:", fm, f"Rule file {rule_file.name} missing 'always_on' in frontmatter"
            )

        # 2. Validate skills/*/SKILL.md
        skills_dir = repo_root / "skills"
        skill_files = list(skills_dir.glob("*/SKILL.md"))
        self.assertGreater(len(skill_files), 0, "No skill markdown files found")

        for skill_file in skill_files:
            content = skill_file.read_text(encoding="utf-8")
            self.assertTrue(
                content.startswith("---\n"),
                f"Skill file {skill_file} missing opening YAML frontmatter delimiter '---'",
            )
            parts = content.split("---\n", 2)
            self.assertGreaterEqual(
                len(parts),
                3,
                f"Skill file {skill_file} missing closing YAML frontmatter delimiter '---'",
            )
            fm = parts[1]
            self.assertIn("name:", fm, f"Skill file {skill_file} missing 'name' in frontmatter")
            self.assertIn(
                "description:", fm, f"Skill file {skill_file} missing 'description' in frontmatter"
            )

    def test_hooks_json_schema_contract(self):
        import json

        repo_root = Path(__file__).resolve().parent.parent
        hooks_json_path = repo_root / "hooks.json"
        self.assertTrue(hooks_json_path.exists())

        with open(hooks_json_path, encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("auto-permissions-gate", data)
        gate = data["auto-permissions-gate"]
        self.assertTrue(gate.get("enabled"))

        # PreToolUse is grouped with matcher and hooks
        pre_tool_use = gate.get("PreToolUse", [])
        self.assertIsInstance(pre_tool_use, list)
        for group in pre_tool_use:
            self.assertIn("matcher", group)
            self.assertIn("hooks", group)
            self.assertIsInstance(group["hooks"], list)
            for h in group["hooks"]:
                self.assertIn("command", h)
                self.assertIn("type", h)

        # PreInvocation is a flat list of handler objects (NOT grouped with matcher or nested hooks)
        pre_invocation = gate.get("PreInvocation", [])
        self.assertIsInstance(pre_invocation, list)
        for handler in pre_invocation:
            self.assertIn("command", handler)
            self.assertIn("type", handler)
            self.assertNotIn("matcher", handler)
            self.assertNotIn("hooks", handler)


if __name__ == "__main__":
    unittest.main()
