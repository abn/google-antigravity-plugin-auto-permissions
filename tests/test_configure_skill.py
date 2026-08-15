#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest

from hooks.policy_engine import (
    PROJECT_CONFIG_REL_PATH,
    PROJECT_LOCAL_CONFIG_REL_PATH,
    SESSION_OVERRIDES_FILENAME,
    add_guideline_to_scope,
    add_rule_to_scope,
    add_skill_path_to_scope,
    load_policy_file,
    remove_guideline_from_scope,
    remove_rule_from_scope,
    update_classifier_settings_in_scope,
)

script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../skills/auto-permissions-configure/scripts/configure_permissions.py",
    )
)
spec = importlib.util.spec_from_file_location("configure_permissions", script_path)
configure_permissions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure_permissions)

get_effective_configuration = configure_permissions.get_effective_configuration
format_markdown_summary = configure_permissions.format_markdown_summary


class TestConfigureSkill(unittest.TestCase):
    def test_configure_rules_and_guidelines(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as session_dir:
            # 1. Add static rule to project
            add_rule_to_scope(
                rule_str="command(pytest -v)",
                decision="allow",
                scope="project",
                workspace_dir=ws,
            )

            proj_file = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
            policy = load_policy_file(proj_file)
            self.assertIn("command(pytest -v)", policy["allow"])

            # 2. Add guideline to session
            add_guideline_to_scope(
                guideline="Treat *.corp as safe",
                scope="session",
                session_dir=session_dir,
            )

            session_file = os.path.join(session_dir, "auto-permissions", SESSION_OVERRIDES_FILENAME)
            session_policy = load_policy_file(session_file)
            self.assertIn("Treat *.corp as safe", session_policy["custom_guidelines"])

            # 3. Add skill path to project_local
            add_skill_path_to_scope(
                path_str="~/.nowledge-mem/skills-active",
                scope="project_local",
                workspace_dir=ws,
            )

            local_file = os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH)
            local_policy = load_policy_file(local_file)
            self.assertIn("~/.nowledge-mem/skills-active", local_policy["allowed_skill_paths"])

            # 4. Remove rule and guideline
            remove_rule_from_scope(
                rule_str="command(pytest -v)",
                scope="project",
                workspace_dir=ws,
            )
            updated_proj = load_policy_file(proj_file)
            self.assertNotIn("command(pytest -v)", updated_proj["allow"])

            remove_guideline_from_scope(
                guideline="Treat *.corp as safe",
                scope="session",
                session_dir=session_dir,
            )
            updated_session = load_policy_file(session_file)
            self.assertNotIn("Treat *.corp as safe", updated_session["custom_guidelines"])

    def test_update_classifier_settings(self):
        with tempfile.TemporaryDirectory() as ws:
            update_classifier_settings_in_scope(
                settings={
                    "provider": "openai",
                    "model": "gemma-2-9b-it",
                    "endpoint_url": "http://localhost:8000/v1/chat/completions",
                },
                scope="project_local",
                workspace_dir=ws,
            )

            local_file = os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH)
            local_policy = load_policy_file(local_file)
            self.assertEqual(local_policy["provider"], "openai")
            self.assertEqual(local_policy["model"], "gemma-2-9b-it")
            self.assertEqual(
                local_policy["endpoint_url"], "http://localhost:8000/v1/chat/completions"
            )

    def test_configure_timeout_setting(self):
        with tempfile.TemporaryDirectory() as ws:
            update_classifier_settings_in_scope(
                settings={"timeout": 8.0},
                scope="project",
                workspace_dir=ws,
            )

            proj_file = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
            proj_policy = load_policy_file(proj_file)
            self.assertEqual(proj_policy["timeout"], 8.0)

            config_info = get_effective_configuration(workspace_dir=ws)
            self.assertEqual(config_info["effective_classifier"]["timeout_secs"], 8.0)

            md = format_markdown_summary(config_info)
            self.assertIn("Classifier Timeout", md)
            self.assertIn("8.0s", md)

    def test_get_effective_configuration_and_summary(self):
        with tempfile.TemporaryDirectory() as ws:
            config_info = get_effective_configuration(workspace_dir=ws)
            self.assertIn("effective_classifier", config_info)
            self.assertIn("scopes", config_info)

            md = format_markdown_summary(config_info)
            self.assertIn("Auto-Permissions Effective Configuration", md)
            self.assertIn("Policy Scopes & Rules", md)

    def test_probe_classifier_provider(self):
        from unittest.mock import patch

        probe_fn = configure_permissions.probe_classifier_provider

        # Test success path
        with patch("hooks.classifier.classify_tool_call") as mock_classify:
            mock_classify.return_value = (
                "<payload>",
                {"decision": "allow", "reason": "Safe", "risk_category": "safe_routine"},
                None,
                15.2,
            )
            is_healthy, msg, latency = probe_fn(
                provider="openai",
                model="gemma-4-it",
                endpoint_url="http://localhost:13305/v1/chat/completions",
            )
            self.assertTrue(is_healthy)
            self.assertIn("Connected to openai (gemma-4-it)", msg)
            self.assertEqual(latency, 15.2)

        # Test failure path
        with patch("hooks.classifier.classify_tool_call") as mock_classify:
            mock_classify.return_value = (
                "<payload>",
                {
                    "decision": "ask",
                    "reason": "Classifier fallback on error (openai): HTTP 401 Unauthorized",
                    "risk_category": "classifier_error_fallback",
                },
                "HTTP 401 Unauthorized: Invalid key",
                8.4,
            )
            is_healthy, msg, latency = probe_fn(
                provider="openai",
                model="gemma-4-it",
                endpoint_url="http://localhost:13305/v1/chat/completions",
            )
            self.assertFalse(is_healthy)
            self.assertIn("HTTP 401 Unauthorized", msg)

    def test_configure_trust_workspace_writes(self):
        with tempfile.TemporaryDirectory() as ws:
            # Test disabling trust_workspace_writes
            configure_permissions.update_trust_workspace_writes_setting(
                enabled=False,
                scope="project",
                workspace_dir=ws,
            )
            config_info = get_effective_configuration(workspace_dir=ws)
            self.assertFalse(config_info["effective_trust_workspace_writes"])

            md = format_markdown_summary(config_info)
            self.assertIn("Disabled", md)

            # Test re-enabling trust_workspace_writes
            configure_permissions.update_trust_workspace_writes_setting(
                enabled=True,
                scope="project",
                workspace_dir=ws,
            )
            config_info2 = get_effective_configuration(workspace_dir=ws)
            self.assertTrue(config_info2["effective_trust_workspace_writes"])

    def test_configure_show_turn_summary(self):
        with tempfile.TemporaryDirectory() as ws:
            # Test disabling show_turn_summary
            configure_permissions.update_show_turn_summary_setting(
                enabled=False,
                scope="project",
                workspace_dir=ws,
            )
            config_info = get_effective_configuration(workspace_dir=ws)
            self.assertFalse(config_info["effective_show_turn_summary"])

            md = format_markdown_summary(config_info)
            self.assertIn("Disabled (Opt-Out)", md)

            # Test re-enabling show_turn_summary
            configure_permissions.update_show_turn_summary_setting(
                enabled=True,
                scope="project",
                workspace_dir=ws,
            )
            config_info2 = get_effective_configuration(workspace_dir=ws)
            self.assertTrue(config_info2["effective_show_turn_summary"])


if __name__ == "__main__":
    unittest.main()
