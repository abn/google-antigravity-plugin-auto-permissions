#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestPreInvocationHook(unittest.TestCase):
    def test_pre_invocation_with_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock audit.jsonl in tmpdir
            audit_path = os.path.join(tmpdir, "audit.jsonl")
            record = {
                "timestamp": "2026-08-14T12:00:00Z",
                "conversationId": "test-session-123",
                "stepIdx": 2,
                "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest"}},
                "hook_output": {"decision": "allow", "reason": "Safe test"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 150.0,
                },
            }
            with open(audit_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

            payload = {
                "conversationId": "test-session-123",
                "artifactDirectoryPath": tmpdir,
                "invocationNum": 1,
            }

            hook_script = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../hooks/pre_invocation.py")
            )
            res = subprocess.run(
                [sys.executable, hook_script],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )

            out = json.loads(res.stdout.strip())
            self.assertIn("injectSteps", out)
            self.assertEqual(len(out["injectSteps"]), 1)
            msg = out["injectSteps"][0]["ephemeralMessage"]
            self.assertIn("Auto-Permissions Security Gate Advisory", msg)
            self.assertIn("<details>", msg)
            self.assertIn("🟢 **ALLOW**", msg)

    def test_pre_invocation_without_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = {
                "conversationId": "empty-session",
                "artifactDirectoryPath": tmpdir,
                "invocationNum": 0,
            }

            hook_script = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../hooks/pre_invocation.py")
            )
            res = subprocess.run(
                [sys.executable, hook_script],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
            )

            out = json.loads(res.stdout.strip())
            self.assertEqual(out, {"injectSteps": []})

    def test_pre_invocation_empty_stdin(self):
        hook_script = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../hooks/pre_invocation.py")
        )
        res = subprocess.run(
            [sys.executable, hook_script],
            input="",
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(res.stdout.strip())
        self.assertEqual(out, {"injectSteps": []})


if __name__ == "__main__":
    unittest.main()
