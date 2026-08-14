#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch

script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../skills/auto-permissions-test/scripts/test_permission.py",
    )
)
spec = importlib.util.spec_from_file_location("test_permission", script_path)
test_permission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_permission)

evaluate_simulated_permission = test_permission.evaluate_simulated_permission
format_markdown_report = test_permission.format_markdown_report


class TestPermissionSkill(unittest.TestCase):
    def test_evaluate_simulated_permission_static_match(self):
        with tempfile.TemporaryDirectory() as ws:
            # Command matching pytest
            res = evaluate_simulated_permission(
                active_prompt="run tests",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest -v"},
                workspace_paths=[ws],
            )
            # Default fallback or static
            self.assertIn("decision", res)
            self.assertIn("model_response", res)
            self.assertIn("<proposed_tool_call>", res["raw_prompt"])

    @patch("hooks.classifier.urllib.request.urlopen")
    def test_evaluate_simulated_permission_classifier_mock(self, mock_urlopen):
        import json
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "decision": "deny",
                                            "reason": "Pushing unrequested branch",
                                            "risk_category": "scope_deviation",
                                            "confidence": 0.95,
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        ).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = evaluate_simulated_permission(
            active_prompt="update readme",
            tool_name="run_command",
            tool_args={"CommandLine": "git push origin main"},
            workspace_paths=["/tmp"],
            api_key="mock-key",
        )

        self.assertEqual(res["decision"], "deny")
        self.assertEqual(res["risk_category"], "scope_deviation")

        md = format_markdown_report(
            active_prompt="update readme",
            tool_name="run_command",
            tool_args={"CommandLine": "git push origin main"},
            result=res,
        )
        self.assertIn("🔴 **DENY**", md)
        self.assertIn("<details>", md)
        self.assertIn("Classifier Prompt Payload", md)
        self.assertIn("Model JSON Response", md)


if __name__ == "__main__":
    unittest.main()
