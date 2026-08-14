#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest

from hooks.audit_logger import (
    diagnose_audit_records,
    log_audit_event_async,
    resolve_session_log_path,
    write_audit_record_sync,
)

script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../skills/auto-permissions-audit/scripts/view_audit.py",
    )
)
spec = importlib.util.spec_from_file_location("view_audit", script_path)
view_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(view_audit)

generate_markdown_summary = view_audit.generate_markdown_summary


class TestAuditLogger(unittest.TestCase):
    def test_resolve_session_log_path_with_artifact_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = resolve_session_log_path(artifact_dir=tmpdir)
            self.assertEqual(path, os.path.join(tmpdir, "audit.jsonl"))

    def test_write_and_rotate_audit_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.jsonl")

            # Write records with a very small max_bytes to force rotation
            small_max_bytes = 200
            for i in range(10):
                rec = {"test_index": i, "data": "x" * 50}
                write_audit_record_sync(log_path, rec, max_bytes=small_max_bytes, backup_count=3)

            # Main log file should exist
            self.assertTrue(os.path.exists(log_path))
            # Rotated backup .1 and .2 should exist
            self.assertTrue(os.path.exists(f"{log_path}.1"))
            self.assertTrue(os.path.exists(f"{log_path}.2"))

    def test_async_audit_logger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            thread = log_audit_event_async(
                artifact_dir=tmpdir,
                transcript_path=None,
                conversation_id="test-conv-123",
                step_idx=5,
                tool_call={"name": "run_command", "args": {"CommandLine": "ls"}},
                context={"active_prompt": "list files"},
                raw_prompt="<mock_prompt>",
                classification={"decision": "allow", "reason": "Safe list"},
                hook_output={"decision": "allow", "reason": "Safe list"},
                latency_ms=123.4,
            )
            thread.join(timeout=1.0)

            log_path = os.path.join(tmpdir, "audit.jsonl")
            self.assertTrue(os.path.exists(log_path))
            with open(log_path, encoding="utf-8") as f:
                lines = f.readlines()
                self.assertEqual(len(lines), 1)
                data = json.loads(lines[0])
                self.assertEqual(data["conversationId"], "test-conv-123")
                self.assertEqual(data["classification"]["decision"], "allow")
                self.assertEqual(data["classification"]["latency_ms"], 123.4)

    def test_diagnose_audit_records(self):
        records = [
            {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest -v"}},
                "hook_output": {"decision": "allow", "reason": "Tests safe"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 320.0,
                },
            },
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git push --force origin main"},
                },
                "hook_output": {"decision": "deny", "reason": "Destructive wipe"},
                "classification": {
                    "decision": "deny",
                    "risk_category": "data_exfiltration_or_destruction",
                    "latency_ms": 2500.0,
                },
            },
            {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "npm publish"}},
                "hook_output": {"decision": "ask", "reason": "Missing GEMINI_API_KEY"},
                "classification": {
                    "decision": "ask",
                    "risk_category": "missing_credentials",
                    "latency_ms": 0.0,
                },
            },
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git commit -m 'feat'", "BypassSandbox": True},
                },
                "hook_output": {"decision": "allow", "reason": "User requested commit"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 1200.0,
                },
            },
        ]

        diag = diagnose_audit_records(records)
        self.assertEqual(diag["total_evaluated"], 4)
        self.assertEqual(len(diag["denials"]), 1)
        self.assertEqual(len(diag["sandbox_bypasses"]), 1)
        self.assertEqual(len(diag["high_latency"]), 1)
        self.assertEqual(len(diag["error_fallbacks"]), 1)
        self.assertTrue(len(diag["recommendations"]) >= 3)

    def test_generate_markdown_summary(self):
        records = [
            {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest -v"}},
                "hook_output": {"decision": "allow", "reason": "Tests safe"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 320.0,
                },
            },
            {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "uv lock"}},
                "hook_output": {"decision": "allow", "reason": "Static grant"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "static_policy_project",
                    "latency_ms": 0.2,
                },
            },
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git branch -D staging"},
                },
                "hook_output": {"decision": "deny", "reason": "Scope deviation"},
                "classification": {
                    "decision": "deny",
                    "risk_category": "scope_deviation",
                    "latency_ms": 410.0,
                },
            },
        ]

        md = generate_markdown_summary(records, limit=3)
        self.assertIn("<details>", md)
        self.assertIn("<summary>🛡️ <b>Security Gate Summary:</b> 3 actions evaluated", md)
        self.assertIn("2 allowed, 1 denied", md)
        self.assertIn("🟢 **ALLOW**", md)
        self.assertIn("🔴 **DENY**", md)
        self.assertIn("Static ACL (0.2ms)", md)
        self.assertIn("Gemini (320ms)", md)


if __name__ == "__main__":
    unittest.main()
