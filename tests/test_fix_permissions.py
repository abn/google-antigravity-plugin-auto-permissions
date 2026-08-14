#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest

from hooks.policy_engine import add_rule_to_scope, load_policy_file

# Import fix_permissions from hyphenated path
script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../skills/auto-permissions-fix/scripts/fix_permissions.py",
    )
)
spec = importlib.util.spec_from_file_location("fix_permissions", script_path)
fix_permissions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix_permissions)

load_denied_audit_records = fix_permissions.load_denied_audit_records
suggest_rules_for_tool_call = fix_permissions.suggest_rules_for_tool_call


class TestFixPermissions(unittest.TestCase):
    def test_suggest_rules_for_tool_call(self):
        # Command tool
        rules = suggest_rules_for_tool_call("run_command", {"CommandLine": "uv lock --upgrade"})
        self.assertIn("command(uv lock --upgrade)", rules)
        self.assertIn("command(uv lock)", rules)
        self.assertIn("command(uv)", rules)

        # File write tool
        rules = suggest_rules_for_tool_call(
            "write_to_file", {"TargetFile": "src/components/button.tsx"}
        )
        self.assertIn("write_file(src/components/button.tsx)", rules)
        self.assertIn("write_file(src/components/.*)", rules)

        # URL read tool
        rules = suggest_rules_for_tool_call(
            "read_url_content", {"Url": "https://docs.pytest.org/en/stable/"}
        )
        self.assertIn("read_url(docs.pytest.org)", rules)

    def test_load_denied_audit_records(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as f:
            records = [
                {
                    "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest"}},
                    "hook_output": {"decision": "allow", "reason": "Safe test"},
                },
                {
                    "toolCall": {"name": "run_command", "args": {"CommandLine": "uv lock"}},
                    "hook_output": {"decision": "deny", "reason": "Scope deviation"},
                },
                {
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": "kubectl delete pod app"},
                    },
                    "hook_output": {"decision": "ask", "reason": "High risk infrastructure"},
                },
            ]
            for r in records:
                f.write(json.dumps(r) + "\n")
            log_path = f.name

        try:
            denials = load_denied_audit_records(log_path)
            self.assertEqual(len(denials), 2)
            self.assertEqual(denials[0]["toolCall"]["args"]["CommandLine"], "uv lock")
            self.assertEqual(
                denials[1]["toolCall"]["args"]["CommandLine"], "kubectl delete pod app"
            )
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)

    def test_add_rule_to_scope_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = add_rule_to_scope(
                rule_str="command(uv lock)",
                decision="allow",
                scope="project",
                workspace_dir=tmpdir,
            )
            self.assertTrue(os.path.exists(out_file))
            policy = load_policy_file(out_file)
            self.assertIn("command(uv lock)", policy["allow"])


if __name__ == "__main__":
    unittest.main()
