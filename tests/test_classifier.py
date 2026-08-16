#!/usr/bin/env python3
import json
import unittest
from unittest.mock import MagicMock, patch

from hooks.classifier import _clean_json_text, classify_tool_call, format_classifier_payload


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

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_http_401_error_extraction(self, mock_urlopen):
        import io
        import urllib.error

        error_body = json.dumps({"error": {"message": "Invalid API key provided"}}).encode("utf-8")
        fp = io.BytesIO(error_body)
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.openai.com/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=fp,
        )

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="openai",
            model="gpt-4o-mini",
            api_key="invalid-key",
        )

        self.assertIn("HTTP 401 Unauthorized", str(err))
        self.assertIn("Invalid API key provided", str(err))
        self.assertEqual(decision["decision"], "ask")
        self.assertEqual(decision["risk_category"], "classifier_error_fallback")
        self.assertIn("Invalid API key provided", decision["reason"])

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_http_404_error_extraction(self, mock_urlopen):
        import io
        import urllib.error

        error_body = json.dumps({"error": "Model 'gemma-99b' not found"}).encode("utf-8")
        fp = io.BytesIO(error_body)
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://localhost:13305/v1/chat/completions",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=fp,
        )

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="openai",
            model="gemma-99b",
            endpoint_url="http://localhost:13305/v1/chat/completions",
        )

        self.assertIn("HTTP 404 Not Found", str(err))
        self.assertIn("Model 'gemma-99b' not found", str(err))
        self.assertEqual(decision["decision"], "ask")
        self.assertEqual(decision["risk_category"], "classifier_error_fallback")

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_connection_refused(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError(reason="[Errno 111] Connection refused")

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="openai",
            endpoint_url="http://localhost:13305/v1/chat/completions",
        )

        self.assertIn("Connection refused", str(err))
        self.assertEqual(decision["decision"], "ask")
        self.assertEqual(decision["risk_category"], "classifier_error_fallback")

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_timeout_error(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("The read operation timed out")

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="google",
            api_key="mock-gemini-key",
            timeout_secs=6.0,
        )

        self.assertIn("Request timed out (>6.0s)", str(err))
        self.assertEqual(decision["decision"], "ask")
        self.assertEqual(decision["risk_category"], "classifier_error_fallback")

    def test_clean_json_text_variants(self):
        # 1. Plain JSON
        self.assertEqual(
            _clean_json_text('{"decision": "allow"}'),
            '{"decision": "allow"}',
        )

        # 2. Markdown fence with json tag
        fenced = '```json\n{"decision": "allow", "reason": "ok"}\n```'
        self.assertEqual(
            _clean_json_text(fenced),
            '{"decision": "allow", "reason": "ok"}',
        )

        # 3. Conversational preamble + markdown fence + trailing commentary
        conversational = (
            "Here is the classification result:\n"
            "```json\n"
            '{"decision": "soft_deny", "reason": "out of scope"}\n'
            "```\n"
            "Let me know if you need anything else."
        )
        self.assertEqual(
            _clean_json_text(conversational),
            '{"decision": "soft_deny", "reason": "out of scope"}',
        )

        # 4. Unfenced JSON embedded in text
        unfenced = 'Security verdict: {"decision": "ask", "reason": "check"} was determined.'
        self.assertEqual(
            _clean_json_text(unfenced),
            '{"decision": "ask", "reason": "check"}',
        )


if __name__ == "__main__":
    unittest.main()
