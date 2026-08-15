#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestPreInvocationHook(unittest.TestCase):
    def test_pre_invocation_with_records_turn_scoped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "audit.jsonl")
            transcript_path = os.path.join(tmpdir, "transcript.jsonl")

            # Mock transcript with user prompt at step 10
            with open(transcript_path, "w", encoding="utf-8") as f:
                prompt_step = {"type": "USER_INPUT", "step_index": 10, "content": "Run tests"}
                f.write(json.dumps(prompt_step) + "\n")

            # Audit has an old action (step 5) and a new action in this turn (step 12)
            old_record = {
                "timestamp": "2026-08-14T12:00:00Z",
                "conversationId": "test-session-123",
                "stepIdx": 5,
                "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}},
                "hook_output": {"decision": "allow", "reason": "Old list"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 50.0,
                },
            }
            turn_record = {
                "timestamp": "2026-08-14T12:01:00Z",
                "conversationId": "test-session-123",
                "stepIdx": 12,
                "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest -v"}},
                "hook_output": {"decision": "allow", "reason": "Safe test"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 150.0,
                },
            }
            with open(audit_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(old_record) + "\n")
                f.write(json.dumps(turn_record) + "\n")

            payload = {
                "conversationId": "test-session-123",
                "artifactDirectoryPath": tmpdir,
                "transcriptPath": transcript_path,
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
            msg = out["injectSteps"][0]["ephemeralMessage"]
            self.assertIn("Security Gate Summary", msg)
            self.assertIn("pytest -v", msg)
            self.assertNotIn("`ls`", msg)
            self.assertIn("1 actions in this turn", msg)

    def test_pre_invocation_suppressed_when_no_records_in_active_turn(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "audit.jsonl")
            transcript_path = os.path.join(tmpdir, "transcript.jsonl")

            # Mock transcript with user prompt at step 20
            with open(transcript_path, "w", encoding="utf-8") as f:
                prompt_step = {"type": "USER_INPUT", "step_index": 20, "content": "Just a question"}
                f.write(json.dumps(prompt_step) + "\n")

            # Audit has only old actions at step 5
            old_record = {
                "timestamp": "2026-08-14T12:00:00Z",
                "conversationId": "test-session-123",
                "stepIdx": 5,
                "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}},
                "hook_output": {"decision": "allow", "reason": "Old list"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 50.0,
                },
            }
            with open(audit_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(old_record) + "\n")

            payload = {
                "conversationId": "test-session-123",
                "artifactDirectoryPath": tmpdir,
                "transcriptPath": transcript_path,
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
            self.assertEqual(out, {"injectSteps": []})

    def test_pre_invocation_suppressed_when_opted_out(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "audit.jsonl")
            transcript_path = os.path.join(tmpdir, "transcript.jsonl")
            policy_path = os.path.join(tmpdir, ".agents", "auto-permissions.json")
            os.makedirs(os.path.dirname(policy_path), exist_ok=True)

            with open(transcript_path, "w", encoding="utf-8") as f:
                prompt_step = {"type": "USER_INPUT", "step_index": 10, "content": "Run tests"}
                f.write(json.dumps(prompt_step) + "\n")

            turn_record = {
                "timestamp": "2026-08-14T12:01:00Z",
                "conversationId": "test-session-123",
                "stepIdx": 12,
                "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest -v"}},
                "hook_output": {"decision": "allow", "reason": "Safe test"},
                "classification": {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "latency_ms": 150.0,
                },
            }
            with open(audit_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(turn_record) + "\n")

            # Opt-out in project policy
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump({"show_turn_summary": False}, f)

            payload = {
                "conversationId": "test-session-123",
                "artifactDirectoryPath": tmpdir,
                "transcriptPath": transcript_path,
                "workspacePaths": [tmpdir],
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
            self.assertEqual(out, {"injectSteps": []})

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
