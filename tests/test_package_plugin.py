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


if __name__ == "__main__":
    unittest.main()
