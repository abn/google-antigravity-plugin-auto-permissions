#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from hooks.policy_engine import (
    PROJECT_CONFIG_REL_PATH,
    PROJECT_LOCAL_CONFIG_REL_PATH,
    add_rule_to_scope,
    evaluate_static_policies,
    is_path_in_workspaces,
    is_safe_session_artifact_read,
    is_ungoverned_surface,
    load_custom_guidelines,
    match_command,
    match_image,
    match_path,
    match_schedule,
    match_subagent,
    match_tool_against_rule,
    match_url,
    parse_resource_rule,
    resolve_classifier_config,
    resolve_configured_model,
    resolve_governed_surfaces,
    update_governed_surfaces_in_scope,
)


class TestPolicyEngine(unittest.TestCase):
    def test_parse_resource_rule(self):
        self.assertEqual(parse_resource_rule("command(uv lock)"), ("command", "uv lock"))
        self.assertEqual(parse_resource_rule("write_file(src/.*)"), ("write_file", "src/.*"))
        self.assertEqual(parse_resource_rule("read_url(github.com)"), ("read_url", "github.com"))
        self.assertIsNone(parse_resource_rule("invalid_syntax"))

    def test_match_command(self):
        self.assertTrue(match_command("uv lock", "uv lock"))
        self.assertTrue(match_command("uv lock", "uv lock --upgrade"))
        self.assertTrue(match_command("pytest", "pytest -v tests/"))
        self.assertTrue(match_command("*", "anything"))
        self.assertFalse(match_command("git push", "git pull"))

    def test_match_path(self):
        self.assertTrue(match_path("src/", "src/module/app.py"))
        self.assertTrue(match_path("/tmp/test.txt", "/tmp/test.txt"))
        self.assertTrue(match_path("tests/.*", "tests/test_auth.py"))
        self.assertTrue(match_path("*", "/any/path"))
        self.assertFalse(match_path("src/", "docs/readme.md"))

    def test_match_url(self):
        self.assertTrue(match_url("github.com", "https://api.github.com/repos"))
        self.assertTrue(match_url("google.com", "https://google.com/search"))
        self.assertTrue(match_url("*", "https://example.com"))
        self.assertFalse(match_url("github.com", "https://gitlab.com"))

    def test_match_tool_against_rule(self):
        # Command tool
        self.assertTrue(
            match_tool_against_rule("command(uv lock)", "run_command", {"CommandLine": "uv lock"})
        )
        self.assertFalse(
            match_tool_against_rule(
                "command(uv lock)", "run_command", {"CommandLine": "cargo build"}
            )
        )

        # Write tool
        self.assertTrue(
            match_tool_against_rule(
                "write_file(src/.*)", "write_to_file", {"TargetFile": "src/app.py"}
            )
        )

        # Read tools
        self.assertTrue(
            match_tool_against_rule(
                "read_file(src/.*)", "view_file", {"AbsolutePath": "src/app.py"}
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "read_file(docs/.*)", "list_dir", {"DirectoryPath": "docs/architecture"}
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "read_file(tests/.*)", "grep_search", {"SearchPath": "tests/test_auth.py"}
            )
        )

        # Read URL tool
        self.assertTrue(
            match_tool_against_rule(
                "read_url(github.com)",
                "read_url_content",
                {"Url": "https://api.github.com/events"},
            )
        )

        # MCP tools
        self.assertTrue(
            match_tool_against_rule(
                "mcp(nowledge-mem:*)",
                "call_mcp_tool",
                {"ServerName": "nowledge-mem", "ToolName": "memory_search"},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "mcp(nowledge-mem:memory_search)",
                "call_mcp_tool",
                {"ServerName": "nowledge-mem", "ToolName": "memory_search"},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "mcp(chrome-devtools:*)",
                "mcp_chrome-devtools_navigate_page",
                {},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "mcp(nowledge-mem:*)",
                "read_resource",
                {"ServerName": "nowledge-mem", "Uri": "nmem://profile"},
            )
        )
        self.assertFalse(
            match_tool_against_rule(
                "mcp(nowledge-mem:memory_search)",
                "call_mcp_tool",
                {"ServerName": "nowledge-mem", "ToolName": "memory_delete"},
            )
        )

    def test_is_path_in_workspaces(self):
        with tempfile.TemporaryDirectory() as ws:
            in_path = os.path.join(ws, "src", "app.py")
            out_path = "/tmp/other_dir/file.txt"
            self.assertTrue(is_path_in_workspaces(in_path, [ws]))
            self.assertFalse(is_path_in_workspaces(out_path, [ws]))

    def test_workspace_read_fast_path(self):
        with tempfile.TemporaryDirectory() as ws:
            target_file = os.path.join(ws, "main.py")
            res = evaluate_static_policies(
                tool_name="view_file",
                tool_args={"AbsolutePath": target_file},
                workspace_paths=[ws],
            )
            self.assertIsNotNone(res)
            decision, _reason, scope = res
            self.assertEqual(decision, "allow")
            self.assertEqual(scope, "workspace_boundary")

    def test_load_custom_guidelines(self):
        with tempfile.TemporaryDirectory() as ws:
            config_file = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "allow": [],
                        "custom_guidelines": [
                            "Treat *.corp.internal requests as safe.",
                            "Do not modify migrations without ask.",
                        ],
                    },
                    f,
                )

            guidelines = load_custom_guidelines(workspace_paths=[ws])
            self.assertIn("Treat *.corp.internal requests as safe.", guidelines)
            self.assertIn("Do not modify migrations without ask.", guidelines)

    def test_resolve_configured_model(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as session_dir:
            # 1. Default fallback
            self.assertEqual(
                resolve_configured_model(session_dir=session_dir, workspace_paths=[ws]),
                "gemini-2.5-flash",
            )

            # 2. Project config override
            config_file = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump({"model": "gemini-2.5-pro"}, f)

            self.assertEqual(
                resolve_configured_model(session_dir=session_dir, workspace_paths=[ws]),
                "gemini-2.5-pro",
            )

            # 3. Session config override takes precedence
            session_file = os.path.join(session_dir, "session_overrides.json")
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump({"model": "gemini-3.5-flash"}, f)

            self.assertEqual(
                resolve_configured_model(session_dir=session_dir, workspace_paths=[ws]),
                "gemini-3.5-flash",
            )

    def test_resolve_classifier_config_multi_provider(self):
        with tempfile.TemporaryDirectory() as ws:
            # 1. Test local untracked config with direct api_key
            local_config = os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH)
            os.makedirs(os.path.dirname(local_config), exist_ok=True)
            with open(local_config, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "provider": "openai",
                        "model": "gemma-2-9b-it",
                        "endpoint_url": "http://localhost:8000/v1/chat/completions",
                        "api_key": "custom-inline-key",
                    },
                    f,
                )

            cfg = resolve_classifier_config(workspace_paths=[ws])
            self.assertEqual(cfg["provider"], "openai")
            self.assertEqual(cfg["model"], "gemma-2-9b-it")
            self.assertEqual(cfg["endpoint_url"], "http://localhost:8000/v1/chat/completions")
            self.assertEqual(cfg["api_key"], "custom-inline-key")

    def test_add_rule_and_evaluate_hierarchy(self):
        with tempfile.TemporaryDirectory() as session_dir, tempfile.TemporaryDirectory() as ws_dir:
            # 1. Add project allow rule: command(uv lock)
            add_rule_to_scope(
                rule_str="command(uv lock)",
                decision="allow",
                scope="project",
                workspace_dir=ws_dir,
            )

            # Evaluate: should be allow from project
            res = evaluate_static_policies(
                tool_name="run_command",
                tool_args={"CommandLine": "uv lock"},
                session_dir=session_dir,
                workspace_paths=[ws_dir],
            )
            self.assertIsNotNone(res)
            decision, _reason, scope = res
            self.assertEqual(decision, "allow")
            self.assertEqual(scope, "project")

            # 2. Add session override with higher priority: deny command(uv lock)
            add_rule_to_scope(
                rule_str="command(uv lock)",
                decision="deny",
                scope="session",
                session_dir=session_dir,
            )

            # Evaluate: session deny should take precedence
            res = evaluate_static_policies(
                tool_name="run_command",
                tool_args={"CommandLine": "uv lock"},
                session_dir=session_dir,
                workspace_paths=[ws_dir],
            )
            self.assertIsNotNone(res)
            decision, _reason, scope = res
            self.assertEqual(decision, "deny")
            self.assertEqual(scope, "session")

    def test_is_path_in_workspaces_symlink_traversal(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as external_dir:
            secret_file = os.path.join(external_dir, "sensitive.txt")
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write("secret data")

            # Symlink inside workspace pointing to external file
            symlink_in_ws = os.path.join(ws, "symlink_to_secret.txt")
            os.symlink(secret_file, symlink_in_ws)

            # abspath looks like it is in ws, but realpath escapes to external_dir
            self.assertFalse(is_path_in_workspaces(symlink_in_ws, [ws]))

    def test_is_safe_skill_read_and_custom_paths(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as custom_skills:
            skill_md = os.path.join(custom_skills, "my-custom-skill", "SKILL.md")
            os.makedirs(os.path.dirname(skill_md), exist_ok=True)
            with open(skill_md, "w", encoding="utf-8") as f:
                f.write("# My Skill")

            # 1. By default, custom external directory is NOT fast-pathed
            res1 = evaluate_static_policies(
                tool_name="view_file",
                tool_args={"AbsolutePath": skill_md, "IsSkillFile": True},
                workspace_paths=[ws],
            )
            self.assertIsNone(res1)

            # 2. Add allowed_skill_paths to project config
            config_file = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump({"allowed_skill_paths": [custom_skills]}, f)

            # 3. Now it is auto-approved on the fast-path!
            res2 = evaluate_static_policies(
                tool_name="view_file",
                tool_args={"AbsolutePath": skill_md, "IsSkillFile": True},
                workspace_paths=[ws],
            )
            self.assertIsNotNone(res2)
            decision, _reason, scope = res2
            self.assertEqual(decision, "allow")
            self.assertEqual(scope, "skill_resource")

    def test_is_safe_skill_read_symlinked_plugin(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as plugin_src:
            # Create a skill inside a source plugin repo
            skill_md = os.path.join(plugin_src, "skills", "auto-permissions-audit", "SKILL.md")
            os.makedirs(os.path.dirname(skill_md), exist_ok=True)
            with open(skill_md, "w", encoding="utf-8") as f:
                f.write("# Audit Skill")

            # Symlink this plugin into workspace .agents/plugins/
            ws_plugins = os.path.join(ws, ".agents", "plugins")
            os.makedirs(ws_plugins, exist_ok=True)
            os.symlink(plugin_src, os.path.join(ws_plugins, "my-plugin"))

            # Reading via logical symlink path in workspace
            logical_path = os.path.join(
                ws_plugins, "my-plugin", "skills", "auto-permissions-audit", "SKILL.md"
            )
            res = evaluate_static_policies(
                tool_name="view_file",
                tool_args={"AbsolutePath": logical_path, "IsSkillFile": True},
                workspace_paths=[ws],
            )
            self.assertIsNotNone(res)
            decision, _reason, scope = res
            self.assertEqual(decision, "allow")
            self.assertEqual(scope, "skill_resource")

    def test_match_subagents_and_schedule_and_image(self):
        # Subagent matching
        self.assertTrue(
            match_subagent(
                "research",
                "invoke_subagent",
                {"Subagents": [{"TypeName": "research", "Role": "Researcher"}]},
            )
        )
        self.assertTrue(
            match_subagent(
                "*",
                "invoke_subagent",
                {"Subagents": [{"TypeName": "code_refactor", "Role": "Refactorer"}]},
            )
        )
        self.assertFalse(
            match_subagent(
                "tester",
                "invoke_subagent",
                {"Subagents": [{"TypeName": "research", "Role": "Researcher"}]},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "subagent(research)",
                "invoke_subagent",
                {"Subagents": [{"TypeName": "research", "Role": "Researcher"}]},
            )
        )

        # Schedule matching
        self.assertTrue(
            match_schedule(
                "cron",
                "schedule",
                {"CronExpression": "*/5 * * * *", "Prompt": "Run check"},
            )
        )
        self.assertTrue(
            match_schedule(
                "timer",
                "schedule",
                {"DurationSeconds": 60, "Prompt": "Reminder"},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "schedule(cron)",
                "schedule",
                {"CronExpression": "*/5 * * * *", "Prompt": "Run check"},
            )
        )

        # Image matching
        self.assertTrue(
            match_image(
                "mockup",
                "generate_image",
                {"ImageName": "dashboard_mockup", "Prompt": "Draw dashboard"},
            )
        )
        self.assertTrue(
            match_tool_against_rule(
                "image(*)",
                "generate_image",
                {"ImageName": "dashboard_mockup", "Prompt": "Draw dashboard"},
            )
        )

    def test_governed_surfaces_opt_in(self):
        with tempfile.TemporaryDirectory() as ws:
            # 1. By default, subagents, schedule, and images are UNGOVERNED (opt-in is False)
            self.assertTrue(is_ungoverned_surface("invoke_subagent", workspace_paths=[ws]))
            self.assertTrue(is_ungoverned_surface("schedule", workspace_paths=[ws]))
            self.assertTrue(is_ungoverned_surface("generate_image", workspace_paths=[ws]))
            self.assertFalse(is_ungoverned_surface("run_command", workspace_paths=[ws]))

            # 2. Opt-in to subagents and schedule in project config
            update_governed_surfaces_in_scope(
                governed={"subagents": True, "schedule": True},
                scope="project",
                workspace_dir=ws,
            )

            # 3. Now subagents and schedule are governed, but images remains ungoverned
            gov = resolve_governed_surfaces(workspace_paths=[ws])
            self.assertTrue(gov["subagents"])
            self.assertTrue(gov["schedule"])
            self.assertFalse(gov["images"])

            self.assertFalse(is_ungoverned_surface("invoke_subagent", workspace_paths=[ws]))
            self.assertFalse(is_ungoverned_surface("schedule", workspace_paths=[ws]))
            self.assertTrue(is_ungoverned_surface("generate_image", workspace_paths=[ws]))

    def test_is_safe_session_artifact_read(self):
        with tempfile.TemporaryDirectory() as session_tmp:
            session_dir = os.path.abspath(session_tmp)
            audit_log = os.path.join(session_dir, "audit.jsonl")
            scratch_dir = os.path.join(session_dir, "scratch")
            scratch_file = os.path.join(scratch_dir, "test.py")
            os.makedirs(scratch_dir, exist_ok=True)
            with open(audit_log, "w", encoding="utf-8") as f:
                f.write("{}\n")
            with open(scratch_file, "w", encoding="utf-8") as f:
                f.write("print('hello')\n")

            # 1. view_file on audit.jsonl and session files
            self.assertTrue(
                is_safe_session_artifact_read(
                    "view_file", {"AbsolutePath": audit_log}, session_dir=session_dir
                )
            )
            self.assertTrue(
                is_safe_session_artifact_read(
                    "view_file", {"AbsolutePath": scratch_file}, session_dir=session_dir
                )
            )

            # 2. list_dir on session directory and subdirectories
            self.assertTrue(
                is_safe_session_artifact_read(
                    "list_dir", {"DirectoryPath": session_dir}, session_dir=session_dir
                )
            )
            self.assertTrue(
                is_safe_session_artifact_read(
                    "list_dir", {"DirectoryPath": scratch_dir}, session_dir=session_dir
                )
            )

            # 3. grep_search on session directory
            self.assertTrue(
                is_safe_session_artifact_read(
                    "grep_search", {"SearchPath": session_dir}, session_dir=session_dir
                )
            )

            # 4. Reject files outside session_dir
            outside_file = "/tmp/other_dir/other.txt"
            self.assertFalse(
                is_safe_session_artifact_read(
                    "view_file", {"AbsolutePath": outside_file}, session_dir=session_dir
                )
            )

            # 5. Reject non-read tools
            self.assertFalse(
                is_safe_session_artifact_read(
                    "write_to_file", {"TargetFile": scratch_file}, session_dir=session_dir
                )
            )

            # 6. evaluate_static_policies fast-path returns ("allow", ..., "session_artifact")
            res = evaluate_static_policies(
                "view_file",
                {"AbsolutePath": audit_log},
                session_dir=session_dir,
            )
            self.assertIsNotNone(res)
            self.assertEqual(res[0], "allow")
            self.assertEqual(res[2], "session_artifact")


if __name__ == "__main__":
    unittest.main()
