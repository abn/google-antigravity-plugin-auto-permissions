#!/usr/bin/env python3
"""
CLI configuration tool for Google Antigravity Auto-Permissions Plugin.
Provides programmatic and interactive configuration of providers, models,
endpoints, static ACL rules, custom semantic guidelines, and skill paths
across Session, Project Local, Project, and Global scopes.
"""

import argparse
import json
import os
import sys
from typing import Any

current_dir = os.path.dirname(os.path.abspath(__file__))
plugin_root = os.path.abspath(os.path.join(current_dir, "../../.."))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from hooks.policy_engine import (  # noqa: E402
    GLOBAL_CONFIG_PATH,
    PROJECT_CONFIG_REL_PATH,
    PROJECT_LOCAL_CONFIG_REL_PATH,
    SESSION_OVERRIDES_FILENAME,
    add_guideline_to_scope,
    add_rule_to_scope,
    add_skill_path_to_scope,
    load_policy_file,
    remove_guideline_from_scope,
    remove_rule_from_scope,
    resolve_classifier_config,
    resolve_scope_file_path,
    update_classifier_settings_in_scope,
)


def get_effective_configuration(
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> dict[str, Any]:
    """Inspects all policy files and returns full aggregated status across scopes."""
    ws = workspace_dir or os.getcwd()
    scopes = {
        "session": (
            os.path.join(session_dir, SESSION_OVERRIDES_FILENAME)
            if session_dir and os.path.isdir(session_dir)
            else None
        ),
        "project_local": os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH),
        "project": os.path.join(ws, PROJECT_CONFIG_REL_PATH),
        "global": GLOBAL_CONFIG_PATH,
    }

    policies_by_scope = {}
    for scope_name, file_path in scopes.items():
        if file_path and os.path.isfile(file_path):
            policies_by_scope[scope_name] = {
                "file_path": file_path,
                "data": load_policy_file(file_path),
            }
        else:
            policies_by_scope[scope_name] = {
                "file_path": file_path,
                "data": None,
            }

    classifier_config = resolve_classifier_config(
        session_dir=session_dir,
        workspace_paths=[ws],
    )

    return {
        "effective_classifier": classifier_config,
        "scopes": policies_by_scope,
    }


def format_markdown_summary(config_info: dict[str, Any]) -> str:
    """Formats configuration status into a clean Markdown table."""
    eff = config_info["effective_classifier"]
    scopes = config_info["scopes"]

    lines = ["### ⚙️ Auto-Permissions Effective Configuration\n"]
    lines.append("| Property | Active Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Provider / Protocol** | `{eff['provider']}` |")
    lines.append(f"| **Model** | `{eff['model']}` |")
    endpoint_display = eff["endpoint_url"] or "*(Default official provider endpoint)*"
    lines.append(f"| **Endpoint URI** | `{endpoint_display}` |")
    key_display = "Set (hidden)" if eff.get("api_key") else "None (Using environment fallback)"
    lines.append(f"| **API Key Status** | {key_display} |")
    lines.append("")

    lines.append("#### 📂 Policy Scopes & Rules\n")
    lines.append("| Scope | Location | Allow Rules | Ask Rules | Deny Rules | Custom Guidelines |")
    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: |")

    for scope_name, s_info in scopes.items():
        f_path = s_info["file_path"] or "*(Not attached)*"
        data = s_info["data"]
        if data:
            allow_cnt = len(data.get("allow", []))
            ask_cnt = len(data.get("ask", []))
            deny_cnt = len(data.get("deny", []))
            gl_cnt = len(data.get("custom_guidelines", []))
            row = (
                f"| **{scope_name}** | `{f_path}` | {allow_cnt} | "
                f"{ask_cnt} | {deny_cnt} | {gl_cnt} |"
            )
            lines.append(row)
        else:
            lines.append(f"| **{scope_name}** | `{f_path}` | - | - | - | - |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Configure Google Antigravity auto-permissions policies across scopes."
    )
    parser.add_argument(
        "--scope",
        "-s",
        choices=["session", "project_local", "project", "global"],
        default="project",
        help="Target configuration scope (default: project).",
    )
    parser.add_argument(
        "--workspace",
        "-w",
        default=os.getcwd(),
        help="Workspace directory root (default: current directory).",
    )
    parser.add_argument(
        "--session-dir",
        "-S",
        help="Session directory path (required for session-scope modifications).",
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List current configuration across all scopes.",
    )
    parser.add_argument(
        "--provider",
        "-P",
        choices=["google", "openai", "anthropic", "gemini", "claude"],
        help="Set classifier provider protocol (google, openai, anthropic).",
    )
    parser.add_argument(
        "--model",
        "-M",
        help="Set classifier model identifier.",
    )
    parser.add_argument(
        "--endpoint-url",
        "-u",
        help="Set custom REST endpoint URL.",
    )
    parser.add_argument(
        "--api-key",
        "-k",
        help="Set direct API key.",
    )
    parser.add_argument(
        "--api-key-env",
        help="Set custom environment variable name to read API key from.",
    )
    parser.add_argument(
        "--add-rule",
        help="Static ACL rule string to add (e.g. 'command(pytest -v)' or 'mcp(stripe:*)').",
    )
    parser.add_argument(
        "--decision",
        "-d",
        choices=["allow", "ask", "deny"],
        default="allow",
        help="Decision bucket for --add-rule (default: allow).",
    )
    parser.add_argument(
        "--remove-rule",
        help="Static ACL rule string to remove.",
    )
    parser.add_argument(
        "--add-guideline",
        help="Custom semantic guideline text to add.",
    )
    parser.add_argument(
        "--remove-guideline",
        help="Custom semantic guideline text to remove.",
    )
    parser.add_argument(
        "--add-skill-path",
        help="Allowed skill directory path to whitelist for fast-path reading.",
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output response as JSON.",
    )
    parser.add_argument(
        "--markdown",
        "-m",
        action="store_true",
        help="Output response as Markdown.",
    )

    args = parser.parse_args()

    workspace_dir = os.path.abspath(args.workspace)
    session_dir = os.path.abspath(args.session_dir) if args.session_dir else None
    scope = args.scope

    actions_performed = []

    # 1. Update classifier settings if specified
    classifier_settings = {}
    if args.provider:
        p = args.provider.lower()
        if p == "gemini":
            p = "google"
        elif p == "claude":
            p = "anthropic"
        classifier_settings["provider"] = p
    if args.model:
        classifier_settings["model"] = args.model.strip()
    if args.endpoint_url:
        classifier_settings["endpoint_url"] = args.endpoint_url.strip()
    if args.api_key:
        classifier_settings["api_key"] = args.api_key.strip()
    if args.api_key_env:
        classifier_settings["api_key_env"] = args.api_key_env.strip()

    if classifier_settings:
        target_file = update_classifier_settings_in_scope(
            settings=classifier_settings,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Updated classifier settings in {scope} ({target_file})")

    # 2. Add rule
    if args.add_rule:
        target_file = add_rule_to_scope(
            rule_str=args.add_rule.strip(),
            decision=args.decision,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(
            f"Added {args.decision} rule '{args.add_rule}' to {scope} ({target_file})"
        )

    # 3. Remove rule
    if args.remove_rule:
        target_file = remove_rule_from_scope(
            rule_str=args.remove_rule.strip(),
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Removed rule '{args.remove_rule}' from {scope} ({target_file})")

    # 4. Add guideline
    if args.add_guideline:
        target_file = add_guideline_to_scope(
            guideline=args.add_guideline.strip(),
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Added custom guideline to {scope} ({target_file})")

    # 5. Remove guideline
    if args.remove_guideline:
        target_file = remove_guideline_from_scope(
            guideline=args.remove_guideline.strip(),
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Removed custom guideline from {scope} ({target_file})")

    # 6. Add skill path
    if args.add_skill_path:
        target_file = add_skill_path_to_scope(
            path_str=args.add_skill_path.strip(),
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Added allowed skill path to {scope} ({target_file})")

    config_info = get_effective_configuration(
        workspace_dir=workspace_dir,
        session_dir=session_dir,
    )
    config_info["actions_performed"] = actions_performed

    if args.json:
        print(json.dumps(config_info, indent=2))
    elif args.markdown or args.list:
        md = format_markdown_summary(config_info)
        if actions_performed:
            md_actions = "\n".join(f"- {a}" for a in actions_performed)
            md = f"**Actions Performed:**\n{md_actions}\n\n{md}"
        print(md)
    else:
        if actions_performed:
            for a in actions_performed:
                print(f"✓ {a}")
        target_f = resolve_scope_file_path(
            scope, workspace_dir=workspace_dir, session_dir=session_dir
        )
        print(f"Policy file updated: {target_f}")


if __name__ == "__main__":
    main()
