#!/usr/bin/env python3
import json
import unittest
from unittest.mock import MagicMock, patch

from hooks.classifier import classify_tool_call, format_classifier_payload


class TestClassifier(unittest.TestCase):
    def test_format_classifier_payload_structure(self):
        payload = format_classifier_payload(
            workspace_paths=["/home/abn/workspace/test-project"],
            prior_prompts=["Setup auth", "Run linter"],
            active_prompt="Run pytest",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            tool_action="Running test suite for auth module",
            tool_summary="Run tests",
            custom_guidelines=[
                "Treat api.internal.corp as safe",
                "Require ask for database migrations",
            ],
        )
        self.assertIn("<workspace_roots>", payload)
        self.assertIn("/home/abn/workspace/test-project", payload)
        self.assertIn("<custom_workspace_guidelines>", payload)
        self.assertIn("- Treat api.internal.corp as safe", payload)
        self.assertIn("- Require ask for database migrations", payload)
        self.assertIn("<prior_user_prompts>", payload)
        self.assertIn("- [Turn -2]: Setup auth", payload)
        self.assertIn("- [Turn -1]: Run linter", payload)
        self.assertIn("<active_user_prompt>", payload)
        self.assertIn("Run pytest", payload)
        self.assertIn("Tool: run_command", payload)
        self.assertIn("Summary: Run tests", payload)
        self.assertIn("Action Intent: Running test suite for auth module", payload)

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_mock_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "decision": "allow",
                                            "reason": "Test execution within scope",
                                            "risk_category": "safe_routine",
                                            "confidence": 1.0,
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            api_key="mock-key",
        )

        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["risk_category"], "safe_routine")
        self.assertGreater(latency, 0.0)

    def test_classify_tool_call_missing_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            raw_payload, decision, err, latency = classify_tool_call(
                workspace_paths=["/tmp"],
                prior_prompts=[],
                active_prompt="Run tests",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest"},
                api_key="",
            )
            self.assertEqual(decision["decision"], "ask")
            self.assertIn("Missing GEMINI_API_KEY", err)


if __name__ == "__main__":
    unittest.main()
