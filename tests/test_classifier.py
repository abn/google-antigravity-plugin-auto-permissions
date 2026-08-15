#!/usr/bin/env python3
import json
import unittest
from unittest.mock import MagicMock, patch

from hooks.classifier import classify_tool_call, format_classifier_payload


class TestClassifier(unittest.TestCase):
    def test_format_classifier_payload_structure(self):
        payload = format_classifier_payload(
            workspace_paths=["/workspace/test-project"],
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
        self.assertIn("/workspace/test-project", payload)
        self.assertIn("<custom_workspace_guidelines>", payload)
        self.assertIn("- Treat api.internal.corp as safe", payload)
        self.assertIn("- Require ask for database migrations", payload)
        self.assertIn("<prior_user_prompts>", payload)
        self.assertIn("- [Turn 0]: Setup auth", payload)
        self.assertIn("- [Turn 1]: Run linter", payload)
        self.assertIn("<active_user_prompt>", payload)
        self.assertIn("Run pytest", payload)
        self.assertIn("Tool: run_command", payload)
        self.assertIn("Summary: Run tests", payload)
        self.assertIn("Action Intent: Running test suite for auth module", payload)

    def test_format_classifier_payload_with_session_anchor(self):
        payload = format_classifier_payload(
            workspace_paths=["/tmp"],
            prior_prompts=[
                "[Session Goal / Turn 0]: Refactor auth and push changes as you go to origin",
                "[Turn 1]: Fix button CSS",
                "[Turn 2]: Update unit tests",
            ],
            active_prompt="Verify and push changes",
            tool_name="run_command",
            tool_args={"CommandLine": "git push origin main"},
        )
        self.assertIn(
            "- [Session Goal / Turn 0]: Refactor auth and push changes as you go to origin", payload
        )
        self.assertIn("- [Turn 1]: Fix button CSS", payload)
        self.assertIn("- [Turn 2]: Update unit tests", payload)
        self.assertIn("Tool: run_command", payload)

    def test_format_classifier_payload_with_session_goal(self):
        payload = format_classifier_payload(
            workspace_paths=["/workspace/test"],
            prior_prompts=["Step 1"],
            active_prompt="Step 2",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            session_goal="Refactor backend authentication service",
        )
        self.assertIn("<session_goal>", payload)
        self.assertIn("Refactor backend authentication service", payload)
        self.assertIn("<active_user_prompt>", payload)

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
                provider="google",
            )
            self.assertEqual(decision["decision"], "ask")
            self.assertIn("GEMINI_API_KEY", err)

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_openai_provider(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision": "allow",
                                    "reason": "OpenAI provider verified safe action",
                                    "risk_category": "safe_routine",
                                    "confidence": 0.95,
                                }
                            )
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
            provider="openai",
            model="gpt-4o-mini",
            api_key="sk-mock-openai-key",
        )

        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["reason"], "OpenAI provider verified safe action")

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_anthropic_provider(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "content": [
                    {
                        "text": "```json\n"
                        + json.dumps(
                            {
                                "decision": "allow",
                                "reason": "Claude verified safe workspace operation",
                                "risk_category": "safe_routine",
                                "confidence": 1.0,
                            }
                        )
                        + "\n```"
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
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
            api_key="sk-ant-mock-key",
        )

        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["reason"], "Claude verified safe workspace operation")


if __name__ == "__main__":
    unittest.main()
