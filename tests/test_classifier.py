#!/usr/bin/env python3
import http.server
import json
import os
import threading
import unittest
from unittest.mock import MagicMock, patch

from hooks.classifier import (
    _call_antigravity_ls_api,
    _call_antigravity_sidecar,
    _clean_json_text,
    _openai_generation_config,
    _resolve_ls_endpoint,
    classify_tool_call,
    format_classifier_payload,
    list_available_models,
)


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

    @patch("hooks.classifier._call_antigravity_ls_api")
    def test_classify_tool_call_antigravity_provider(self, mock_ls_api):
        mock_ls_api.return_value = {
            "decision": "allow",
            "reason": "Antigravity LS verified safe operation",
            "risk_category": "safe_routine",
            "confidence": 0.99,
        }

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="antigravity",
        )

        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["provider"], "antigravity")
        self.assertEqual(decision["reason"], "Antigravity LS verified safe operation")

    @patch("urllib.request.urlopen")
    def test_classify_tool_call_cloudcode_oauth_provider(self, mock_urlopen):
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
                                            "reason": "Cloud Code OAuth verified safe operation",
                                            "risk_category": "safe_routine",
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
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        with patch.dict(os.environ, {"GOOGLE_OAUTH_TOKEN": "ya29.mock_token"}):
            raw_payload, decision, err, latency = classify_tool_call(
                workspace_paths=["/tmp"],
                prior_prompts=[],
                active_prompt="Run tests",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest"},
                provider="cloudcode",
            )

            self.assertIsNone(err)
            self.assertEqual(decision["decision"], "allow")
            self.assertEqual(decision["provider"], "cloudcode")
            self.assertEqual(decision["reason"], "Cloud Code OAuth verified safe operation")

    @patch("hooks.classifier._call_antigravity_ls_api")
    def test_zero_key_fallback_to_antigravity_ls_when_gemini_key_missing(self, mock_ls_api):
        mock_ls_api.return_value = {
            "decision": "allow",
            "reason": "Zero-key LS fallback verified",
            "risk_category": "safe_routine",
            "confidence": 0.97,
        }

        # Clear API keys from environment
        with patch.dict(os.environ, {}, clear=True):
            raw_payload, decision, err, latency = classify_tool_call(
                workspace_paths=["/tmp"],
                prior_prompts=[],
                active_prompt="Run tests",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest"},
                provider="antigravity",
                api_key=None,
            )

            self.assertIsNone(err)
            self.assertEqual(decision["decision"], "allow")
            self.assertEqual(decision["reason"], "Zero-key LS fallback verified")
            mock_ls_api.assert_called_once()

    @patch("hooks.classifier._call_antigravity_ls_api")
    def test_call_antigravity_ls_api_success(self, mock_ls_api):
        mock_ls_api.return_value = {
            "decision": "allow",
            "reason": "Test unit command is safe",
            "risk_category": "safe_routine",
            "confidence": 0.99,
        }

        raw_payload, decision, err, latency = classify_tool_call(
            workspace_paths=["/workspace/app"],
            prior_prompts=["run pytest"],
            active_prompt="run test suite",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest -v"},
            provider="antigravity",
        )

        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["reason"], "Test unit command is safe")
        self.assertEqual(decision["provider"], "antigravity")
        mock_ls_api.assert_called_once()


class TestAntigravityLanguageServer(unittest.TestCase):
    def test_resolve_ls_endpoint_defaults_to_https_for_bare_address(self):
        with patch.dict(
            os.environ,
            {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974", "ANTIGRAVITY_CSRF_TOKEN": "tok"},
        ):
            endpoint, token = _resolve_ls_endpoint()
            self.assertEqual(endpoint, "https://127.0.0.1:39974")
            self.assertEqual(token, "tok")

    def test_resolve_ls_endpoint_normalizes_localhost_and_preserves_scheme(self):
        with patch.dict(
            os.environ,
            {"ANTIGRAVITY_LS_ADDRESS": "http://localhost:38291", "ANTIGRAVITY_CSRF_TOKEN": "tok"},
        ):
            endpoint, _ = _resolve_ls_endpoint()
            self.assertEqual(endpoint, "http://127.0.0.1:38291")

    @patch("hooks.classifier._call_ls_rpc")
    def test_call_antigravity_ls_api_parses_fenced_json(self, mock_rpc):
        # GetModelResponse -> userStatus for roster + single-turn completion.
        mock_rpc.side_effect = [
            {
                "userStatus": {
                    "cascadeModelConfigData": {
                        "clientModelConfigs": [],
                        "defaultOverrideModelConfig": {
                            "modelOrAlias": {"model": "MODEL_GOOGLE_GEMINI_2_5_FLASH"}
                        },
                    }
                }
            },
            {
                "response": '```json\n{"decision": "allow", "reason": "ok", '
                '"risk_category": "safe_routine", "confidence": 0.9}\n```'
            },
        ]
        with patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}):
            parsed = _call_antigravity_ls_api("prompt")
        self.assertEqual(parsed["decision"], "allow")
        self.assertEqual(parsed["provider"], "antigravity")
        self.assertEqual(parsed["confidence"], 0.9)
        model_call = mock_rpc.call_args_list[1]
        self.assertEqual(model_call.args[0], "GetModelResponse")
        self.assertIn("MODEL_GOOGLE_GEMINI_2_5_FLASH", json.dumps(model_call.args[1]))

    @patch("hooks.classifier._call_ls_rpc")
    def test_call_antigravity_ls_api_self_heals_when_resolved_model_404s(self, mock_rpc):
        mock_rpc.side_effect = [
            {
                "userStatus": {
                    "cascadeModelConfigData": {
                        "clientModelConfigs": [
                            {"modelOrAlias": {"model": "MODEL_RETIRED"}, "label": "Old Model"}
                        ],
                        "defaultOverrideModelConfig": {"modelOrAlias": {"model": "MODEL_DEFAULT"}},
                    }
                }
            },
            _HttpError(404),  # requested token retired -> 404
            {"response": '{"decision": "ask", "reason": "healed"}'},
        ]
        with patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}):
            parsed = _call_antigravity_ls_api("prompt", model="MODEL_RETIRED")
        self.assertEqual(parsed["decision"], "ask")
        # second attempt used the default token
        self.assertEqual(mock_rpc.call_args_list[2].args[1]["model"], "MODEL_DEFAULT")

    @patch("hooks.classifier._antigravity_ls_direct")
    def test_antigravity_dispatcher_uses_direct_when_env_present(self, mock_direct):
        mock_direct.return_value = {"decision": "allow"}
        with patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}):
            parsed = _call_antigravity_ls_api("prompt")
        mock_direct.assert_called_once()
        self.assertEqual(parsed["decision"], "allow")

    @patch("hooks.classifier._call_antigravity_sidecar")
    def test_antigravity_dispatcher_uses_sidecar_when_env_absent(self, mock_sidecar):
        mock_sidecar.return_value = {"decision": "ask"}
        with patch.dict(os.environ, {}, clear=True):
            parsed = _call_antigravity_ls_api("prompt")
        mock_sidecar.assert_called_once()
        self.assertEqual(parsed["decision"], "ask")

    def test_antigravity_dispatcher_falls_back_to_sidecar_on_origin_rejection(self):
        import io
        import urllib.error

        origin_err = urllib.error.HTTPError(
            url="https://127.0.0.1:39974/exa.language_server_pb.LanguageServerService/GetModelResponse",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(b"Direct IP access is not allowed"),
        )
        with (
            patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}),
            patch("hooks.classifier._antigravity_ls_direct", side_effect=origin_err) as mock_direct,
            patch(
                "hooks.classifier._call_antigravity_sidecar",
                return_value={"decision": "ask"},
            ) as mock_sidecar,
        ):
            parsed = _call_antigravity_ls_api("prompt")
        mock_direct.assert_called_once()
        mock_sidecar.assert_called_once()
        self.assertEqual(parsed["decision"], "ask")

    def test_antigravity_dispatcher_does_not_fallback_on_other_errors(self):
        with (
            patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}),
            patch("hooks.classifier._antigravity_ls_direct", side_effect=RuntimeError("boom")),
            patch("hooks.classifier._call_antigravity_sidecar") as mock_sidecar,
            self.assertRaises(RuntimeError),
        ):
            _call_antigravity_ls_api("prompt")
        mock_sidecar.assert_not_called()

    def test_antigravity_dispatcher_falls_back_to_sidecar_on_connection_refused(self):
        import urllib.error

        refused = urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        with (
            patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}),
            patch("hooks.classifier._antigravity_ls_direct", side_effect=refused),
            patch(
                "hooks.classifier._call_antigravity_sidecar",
                return_value={"decision": "allow"},
            ) as mock_sidecar,
        ):
            parsed = _call_antigravity_ls_api("prompt")
        mock_sidecar.assert_called_once()
        self.assertEqual(parsed["decision"], "allow")

    def test_antigravity_dispatcher_does_not_fallback_on_real_http_404(self):
        import io
        import urllib.error

        not_found = urllib.error.HTTPError(
            url="https://127.0.0.1:39974/exa.language_server_pb.LanguageServerService/GetModelResponse",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error": {"message": "unknown model"}}'),
        )
        with (
            patch.dict(os.environ, {"ANTIGRAVITY_LS_ADDRESS": "127.0.0.1:39974"}),
            patch("hooks.classifier._antigravity_ls_direct", side_effect=not_found),
            patch("hooks.classifier._call_antigravity_sidecar") as mock_sidecar,
            self.assertRaises(urllib.error.HTTPError),
        ):
            _call_antigravity_ls_api("prompt")
        mock_sidecar.assert_not_called()

    def test_call_antigravity_sidecar_posts_to_classify(self):
        server = _LocalSidecarServer()
        try:
            with patch.dict(os.environ, {"AUTO_PERMISSIONS_SIDECAR_PORT": str(server.port)}):
                parsed = _call_antigravity_sidecar("the-prompt")
        finally:
            server.shutdown()
        self.assertEqual(parsed["decision"], "allow")
        self.assertEqual(server.last_prompt, "the-prompt")

    def test_resolve_ls_model_prefers_fast_stable_model_over_high_effort_default(self):
        from hooks.classifier import DEFAULT_ANTIGRAVITY_MODEL, _resolve_ls_model

        configs = [
            {
                "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M298"},
                "label": "Gemini 3.7 Flash (High)",
            },
            {
                "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M20"},
                "label": "Gemini 3.5 Flash (Medium)",
            },
        ]
        # Even though the account default is a High-effort model, the classifier
        # must prefer the fast stable enum (low thinking level).
        token = _resolve_ls_model(configs, default_id="MODEL_PLACEHOLDER_M298", requested=None)
        self.assertEqual(token, DEFAULT_ANTIGRAVITY_MODEL)

    def test_resolve_ls_model_honors_explicit_request(self):
        from hooks.classifier import _resolve_ls_model

        configs = [
            {
                "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M72"},
                "label": "Gemini 3.6 Flash (Medium)",
            }
        ]
        token = _resolve_ls_model(configs, default_id=None, requested="Gemini 3.6 Flash (Medium)")
        self.assertEqual(token, "MODEL_PLACEHOLDER_M72")

    @patch("hooks.classifier._call_ls_rpc")
    def test_list_available_models_returns_roster(self, mock_rpc):
        mock_rpc.return_value = {
            "userStatus": {
                "cascadeModelConfigData": {
                    "clientModelConfigs": [
                        {
                            "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M298"},
                            "label": "Gemini 3.7 Flash (High)",
                            "isRecommended": True,
                            "quotaInfo": {"remainingFraction": 0.99},
                        },
                        {
                            "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M26"},
                            "label": "Claude Opus 4.6 (Thinking)",
                            "isRecommended": False,
                        },
                    ]
                }
            }
        }
        models = list_available_models()
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0]["id"], "MODEL_PLACEHOLDER_M298")
        self.assertEqual(models[0]["label"], "Gemini 3.7 Flash (High)")
        self.assertEqual(models[0]["quota_remaining"], 0.99)

    @patch("hooks.classifier._call_ls_rpc")
    def test_list_available_models_fails_closed(self, mock_rpc):
        mock_rpc.side_effect = Exception("boom")
        self.assertEqual(list_available_models(), [])


class _HttpError(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code}")


class _LocalSidecarServer:
    """In-process stand-in for the plugin sidecar's /classify endpoint."""

    def __init__(self):
        self.last_prompt = None
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self, *args, **kwargs):  # noqa: ANN002
        server = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                server.last_prompt = body.get("prompt")
                payload = {
                    "decision": "allow",
                    "reason": "sidecar verified safe operation",
                    "risk_category": "safe_routine",
                    "confidence": 1.0,
                    "provider": "antigravity",
                }
                out = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        H(*args, **kwargs)

    def shutdown(self):
        self._server.shutdown()


class TestOpenAIGenerationConfig(unittest.TestCase):
    def test_defaults_target_deterministic_latency_bounded_gate(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = _openai_generation_config()
        self.assertEqual(cfg["temperature"], 0.0)
        self.assertEqual(cfg["top_p"], 1.0)
        self.assertEqual(cfg["max_tokens"], 800)
        self.assertNotIn("top_k", cfg)
        self.assertNotIn("seed", cfg)
        self.assertNotIn("reasoning_effort", cfg)

    def test_env_overrides(self):
        with patch.dict(
            os.environ,
            {
                "AUTO_PERMISSIONS_TEMPERATURE": "0.3",
                "AUTO_PERMISSIONS_TOP_P": "0.9",
                "AUTO_PERMISSIONS_TOP_K": "40",
                "AUTO_PERMISSIONS_MAX_TOKENS": "256",
                "AUTO_PERMISSIONS_SEED": "7",
                "AUTO_PERMISSIONS_REASONING_EFFORT": "low",
            },
        ):
            cfg = _openai_generation_config()
        self.assertEqual(cfg["temperature"], 0.3)
        self.assertEqual(cfg["top_p"], 0.9)
        self.assertEqual(cfg["top_k"], 40)
        self.assertEqual(cfg["max_tokens"], 256)
        self.assertEqual(cfg["seed"], 7)
        self.assertEqual(cfg["reasoning_effort"], "low")

    def test_max_tokens_zero_uses_server_default(self):
        with patch.dict(os.environ, {"AUTO_PERMISSIONS_MAX_TOKENS": "0"}):
            cfg = _openai_generation_config()
        self.assertNotIn("max_tokens", cfg)

    @patch("urllib.request.urlopen")
    def test_request_body_carries_config_and_json_mode_toggle(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision": "allow",
                                    "reason": "ok",
                                    "risk_category": "safe_routine",
                                    "confidence": 0.9,
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        kwargs = dict(
            workspace_paths=["/tmp"],
            prior_prompts=[],
            active_prompt="Run tests",
            tool_name="run_command",
            tool_args={"CommandLine": "pytest"},
            provider="openai",
            model="gpt-4o-mini",
            api_key="k",
        )

        with patch.dict(
            os.environ,
            {"AUTO_PERMISSIONS_TOP_K": "40", "AUTO_PERMISSIONS_REASONING_EFFORT": "low"},
        ):
            _, decision, err, _ = classify_tool_call(**kwargs)
        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        self.assertEqual(body["temperature"], 0.0)
        self.assertEqual(body["top_k"], 40)
        self.assertEqual(body["reasoning_effort"], "low")
        self.assertEqual(body["response_format"], {"type": "json_object"})

        with patch.dict(os.environ, {"AUTO_PERMISSIONS_JSON_MODE": "0"}):
            _, _, err, _ = classify_tool_call(**kwargs)
        self.assertIsNone(err)
        body2 = json.loads(mock_urlopen.call_args[0][0].data.decode())
        self.assertNotIn("response_format", body2)

    def test_system_instruction_contains_explicit_path_guidance(self):
        from hooks.classifier import SYSTEM_INSTRUCTION

        self.assertIn("where the target path/file is explicitly", SYSTEM_INSTRUCTION)
        self.assertIn("UNLESS the user prompt explicitly names, asks about", SYSTEM_INSTRUCTION)
        self.assertIn("reading or inspecting that", SYSTEM_INSTRUCTION)

    @patch("urllib.request.urlopen")
    def test_explicit_user_path_in_question_prompt_allows_inspection(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision": "allow",
                                    "reason": "User explicitly asked to inspect audit log.",
                                    "risk_category": "safe_routine",
                                    "confidence": 1.0,
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        target_path = "/home/abn/.gemini/antigravity/brain/277dcc0e/auto-permissions/audit.jsonl"
        raw_prompt, decision, err, _ = classify_tool_call(
            workspace_paths=["/home/abn/workspace/test-project"],
            prior_prompts=[],
            active_prompt=f"How many requests were prevented in {target_path} ?",
            tool_name="view_file",
            tool_args={"AbsolutePath": target_path},
            provider="openai",
            model="gpt-4o-mini",
            api_key="mock-key",
        )
        self.assertIsNone(err)
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["risk_category"], "safe_routine")
        self.assertIn("/home/abn/.gemini/antigravity/brain/277dcc0e", raw_prompt)


if __name__ == "__main__":
    unittest.main()
