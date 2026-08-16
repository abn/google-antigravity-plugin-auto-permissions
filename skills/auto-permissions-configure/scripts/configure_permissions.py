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

import hooks.classifier as classifier_module  # noqa: E402
from hooks.policy_engine import (  # noqa: E402
    add_guideline_to_scope,
    add_rule_to_scope,
    add_skill_path_to_scope,
    find_bundle_definition,
    list_available_bundles,
    load_policy_file,
    migrate_config_layout,
    remove_guideline_from_scope,
    remove_rule_from_scope,
    resolve_active_bundles,
    resolve_classifier_config,
    resolve_governed_surfaces,
    resolve_scope_file_path,
    resolve_show_turn_summary,
    resolve_trust_workspace_writes,
    update_bundles_in_scope,
    update_classifier_settings_in_scope,
    update_governed_surfaces_in_scope,
    update_show_turn_summary_setting,
    update_trust_workspace_writes_setting,
)


def probe_classifier_provider(
    provider: str,
    model: str,
    endpoint_url: str | None = None,
    api_key: str | None = None,
    timeout_secs: float = 3.5,
) -> tuple[bool, str, float]:
    """
    Sends a lightweight pre-flight probe to verify endpoint connectivity and credentials.
    Returns: (is_healthy, status_message, latency_ms)
    """
    _, classification, error, latency = classifier_module.classify_tool_call(
        workspace_paths=[os.getcwd()],
        prior_prompts=[],
        active_prompt="Health-check probe verification",
        tool_name="run_command",
        tool_args={"CommandLine": "echo 'connectivity-probe'"},
        provider=provider,
        model=model,
        endpoint_url=endpoint_url,
        api_key=api_key,
        timeout_secs=timeout_secs,
    )
    if error or classification.get("risk_category") == "classifier_error_fallback":
        err_msg = error or classification.get("reason", "Unknown connection error")
        return False, err_msg, latency
    return True, f"Connected to {provider} ({model})", latency


def get_effective_configuration(
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> dict[str, Any]:
    """Inspects all policy files and returns full aggregated status across scopes."""
    ws = workspace_dir or os.getcwd()
    scopes = {
        "session": (
            resolve_scope_file_path("session", session_dir=session_dir)
            if session_dir and os.path.isdir(session_dir)
            else None
        ),
        "project_local": resolve_scope_file_path("project_local", workspace_dir=ws),
        "project": resolve_scope_file_path("project", workspace_dir=ws),
        "global": resolve_scope_file_path("global"),
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
    governed_surfaces = resolve_governed_surfaces(
        session_dir=session_dir,
        workspace_paths=[ws],
    )
    trust_writes = resolve_trust_workspace_writes(
        session_dir=session_dir,
        workspace_paths=[ws],
    )
    show_summary = resolve_show_turn_summary(
        session_dir=session_dir,
        workspace_paths=[ws],
    )
    active_bundles = resolve_active_bundles(
        session_dir=session_dir,
        workspace_paths=[ws],
    )
    available_bundles = list_available_bundles(
        session_dir=session_dir,
        workspace_paths=[ws],
    )

    return {
        "effective_classifier": classifier_config,
        "effective_governed_surfaces": governed_surfaces,
        "effective_trust_workspace_writes": trust_writes,
        "effective_show_turn_summary": show_summary,
        "effective_bundles": active_bundles,
        "available_bundles": available_bundles,
        "scopes": policies_by_scope,
    }


def format_markdown_summary(config_info: dict[str, Any]) -> str:
    """Formats configuration status into a clean Markdown table."""
    eff = config_info["effective_classifier"]
    gov = config_info.get("effective_governed_surfaces", {})
    trust_writes = config_info.get("effective_trust_workspace_writes", True)
    show_summary = config_info.get("effective_show_turn_summary", True)
    active_b = config_info.get("effective_bundles", {})
    act_names = active_b.get("active_bundles", [])
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
    timeout_secs = eff.get("timeout_secs", 6.0)
    lines.append(f"| **Classifier Timeout** | `{timeout_secs:.1f}s` *(Default: 6.0s)* |")
    write_trust_display = (
        "⚡ **Enabled (0.1ms fast-path, sensitive paths guarded)** *(Default)*"
        if trust_writes
        else "🔒 **Disabled** (Full LLM classification required on first file write)"
    )
    lines.append(f"| **Workspace Writes Trust** | {write_trust_display} |")
    summary_display = (
        "👁️ **Enabled** (Turn-scoped `<details>` summary on final response) *(Default)*"
        if show_summary
        else "🔇 **Disabled (Opt-Out)**"
    )
    lines.append(f"| **Security Gate Summary** | {summary_display} |")
    bundles_display = (
        ", ".join(f"`{name}`" for name in act_names) if act_names else "*(None active)*"
    )
    lines.append(f"| **Active Bundles** | 📦 {bundles_display} |")
    lines.append("")

    if act_names:
        lines.append("#### 📦 Active Permission Bundles\n")
        lines.append("| Bundle Slug | Allow Rules | Ask Rules | Deny Rules | Guidelines |")
        lines.append("| :--- | :---: | :---: | :---: | :---: |")
        avail = config_info.get("available_bundles", {})
        for b_name in act_names:
            b_def = avail.get(b_name, {})
            al_cnt = len(b_def.get("allow", []))
            as_cnt = len(b_def.get("ask", []))
            de_cnt = len(b_def.get("deny", []))
            gl_cnt = len(b_def.get("custom_guidelines", []))
            lines.append(f"| **`{b_name}`** | {al_cnt} | {as_cnt} | {de_cnt} | {gl_cnt} |")
        lines.append("")

    lines.append("#### 🛡️ Governed Tool Surfaces\n")
    lines.append("| Surface Category | Tools | Active Status |")
    lines.append("| :--- | :--- | :--- |")
    sub_mode = (
        "🔒 **Governed** (Full Classifier)"
        if gov.get("subagents")
        else "⚡ **Fast-Path Allowed** *(Default opt-in)*"
    )
    sched_mode = (
        "🔒 **Governed** (Full Classifier)"
        if gov.get("schedule")
        else "⚡ **Fast-Path Allowed** *(Default opt-in)*"
    )
    img_mode = (
        "🔒 **Governed** (Full Classifier)"
        if gov.get("images")
        else "⚡ **Fast-Path Allowed** *(Default opt-in)*"
    )
    lines.append(
        f"| **Subagents** | `invoke_subagent`, `define_subagent`, `manage_subagents` | {sub_mode} |"
    )
    lines.append(f"| **Scheduling** | `schedule` (cron / timers) | {sched_mode} |")
    lines.append(f"| **Image Generation** | `generate_image` | {img_mode} |")
    lines.append("")

    lines.append("#### 📂 Policy Scopes & Rules\n")
    lines.append(
        "| Scope | Location | Bundles | Allow Rules | Ask Rules | Deny Rules | Custom Guidelines |"
    )
    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |")

    for scope_name, s_info in scopes.items():
        f_path = s_info["file_path"] or "*(Not attached)*"
        data = s_info["data"]
        if data:
            raw_b = data.get("bundles", [])
            if isinstance(raw_b, list):
                b_cnt = len(raw_b)
            elif isinstance(raw_b, dict):
                b_cnt = len(raw_b.get("enabled", []))
            else:
                b_cnt = 0
            allow_cnt = len(data.get("allow", []))
            ask_cnt = len(data.get("ask", []))
            deny_cnt = len(data.get("deny", []))
            gl_cnt = len(data.get("custom_guidelines", []))
            row = (
                f"| **{scope_name}** | `{f_path}` | {b_cnt} | {allow_cnt} | "
                f"{ask_cnt} | {deny_cnt} | {gl_cnt} |"
            )
            lines.append(row)
        else:
            lines.append(f"| **{scope_name}** | `{f_path}` | - | - | - | - | - |")

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
        "--list-bundles",
        action="store_true",
        help="List all available built-in, global, and project permission bundles.",
    )
    parser.add_argument(
        "--bundle-info",
        metavar="BUNDLE_NAME",
        help="Display detailed rules and description for a specific bundle.",
    )
    parser.add_argument(
        "--enable-bundle",
        "-b",
        action="append",
        dest="enable_bundles",
        help="Bundle to enable in target scope (e.g. 'gh-readonly', 'python-tooling').",
    )
    parser.add_argument(
        "--disable-bundle",
        action="append",
        dest="disable_bundles",
        help="Permission bundle name to disable/mask in the target scope.",
    )
    parser.add_argument(
        "--migrate-layout",
        action="store_true",
        help="Migrate flat config files to scoped layout (.agents/auto-permissions/).",
    )
    parser.add_argument(
        "--provider",
        "-P",
        choices=[
            "antigravity",
            "google",
            "cloudcode",
            "openai",
            "anthropic",
            "gemini",
            "claude",
            "sidecar",
            "worker",
            "oauth",
        ],
        metavar="PROVIDER",
        help=(
            "Set classifier provider (canonical: antigravity, google, "
            "cloudcode, openai, anthropic; aliases: gemini, claude, sidecar, oauth)."
        ),
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
        "--govern-subagents",
        action="store_true",
        default=None,
        help="Opt-in to security gate governance for subagent invocations.",
    )
    parser.add_argument(
        "--no-govern-subagents",
        action="store_true",
        default=None,
        help="Disable security gate governance for subagents (fast-path allow).",
    )
    parser.add_argument(
        "--govern-schedule",
        action="store_true",
        default=None,
        help="Opt-in to security gate governance for scheduled crons and timers.",
    )
    parser.add_argument(
        "--no-govern-schedule",
        action="store_true",
        default=None,
        help="Disable security gate governance for schedule (fast-path allow).",
    )
    parser.add_argument(
        "--govern-images",
        action="store_true",
        default=None,
        help="Opt-in to security gate governance for generate_image calls.",
    )
    parser.add_argument(
        "--no-govern-images",
        action="store_true",
        default=None,
        help="Disable security gate governance for images (fast-path allow).",
    )
    parser.add_argument(
        "--trust-workspace-writes",
        dest="trust_workspace_writes",
        action="store_true",
        default=None,
        help="Enable 0.1ms fast-path for non-sensitive workspace writes (default: True).",
    )
    parser.add_argument(
        "--no-trust-workspace-writes",
        dest="trust_workspace_writes",
        action="store_false",
        default=None,
        help="Disable workspace writes fast-path (force LLM classifier on first write).",
    )
    parser.add_argument(
        "--show-turn-summary",
        dest="show_turn_summary",
        action="store_true",
        default=None,
        help="Enable turn-scoped security gate summary disclosure in final responses.",
    )
    parser.add_argument(
        "--no-show-turn-summary",
        dest="show_turn_summary",
        action="store_false",
        default=None,
        help="Disable (opt-out of) turn-scoped security gate summary disclosure.",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        help="Set classifier timeout in seconds across scopes (default: 6.0s).",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        default=True,
        help="Run pre-flight health check probe when updating provider/endpoint (default: True).",
    )
    parser.add_argument(
        "--no-probe",
        dest="probe",
        action="store_false",
        help="Bypass pre-flight health check probe (e.g. for offline local setup).",
    )
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="Test connectivity of current or specified classifier provider and exit.",
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
    session_dir = (
        os.path.abspath(args.session_dir)
        if args.session_dir
        else os.environ.get("AUTO_PERMISSIONS_SESSION_DIR")
        or os.environ.get("ANTIGRAVITY_ARTIFACT_DIR")
    )
    if session_dir:
        session_dir = os.path.abspath(session_dir)
    scope = args.scope

    # Dedicated migration mode
    if args.migrate_layout:
        mig_res = migrate_config_layout(workspace_dir=workspace_dir, migrate_global=True)
        if args.json:
            print(json.dumps({"migrated": mig_res}, indent=2))
        else:
            if mig_res:
                print("📦 Scoped Directory Layout Migration Complete:")
                for k, msg in mig_res.items():
                    print(f"  ✓ {k}: {msg}")
            else:
                print(
                    "✓ Config files already use scoped directory layout "
                    "(.agents/auto-permissions/)."
                )
        sys.exit(0)

    # Dedicated list-bundles mode
    if args.list_bundles:
        avail_bundles = list_available_bundles(
            workspace_paths=[workspace_dir], session_dir=session_dir
        )
        active_info = resolve_active_bundles(
            workspace_paths=[workspace_dir], session_dir=session_dir
        )
        active_set = set(active_info.get("active_bundles", []))

        if args.json:
            print(
                json.dumps(
                    {"active_bundles": list(active_set), "available_bundles": avail_bundles},
                    indent=2,
                )
            )
        else:
            print("### 📦 Available Permission Bundles\n")
            print("| Status | Slug | Source | Description | Rules Count |")
            print("| :---: | :--- | :--- | :--- | :---: |")
            for b_slug, b_data in sorted(avail_bundles.items()):
                status = "🟢 Enabled" if b_slug in active_set else "⚪ Available"
                src = b_data.get("source", "builtin")
                desc = b_data.get("description", "")
                r_cnt = (
                    len(b_data.get("allow", []))
                    + len(b_data.get("ask", []))
                    + len(b_data.get("deny", []))
                )
                print(f"| {status} | **`{b_slug}`** | `{src}` | {desc} | {r_cnt} |")
        sys.exit(0)

    # Dedicated bundle-info mode
    if args.bundle_info:
        b_name = args.bundle_info.strip().lower()
        b_def = find_bundle_definition(b_name, workspace_paths=[workspace_dir])
        if not b_def:
            print(f"❌ Bundle '{b_name}' not found.")
            sys.exit(1)
        if args.json:
            print(json.dumps(b_def, indent=2))
        else:
            print(f"### 📦 Bundle: `{b_def.get('name', b_name)}`\n")
            print(f"**Description:** {b_def.get('description', 'N/A')}")
            print(f"**Source:** `{b_def.get('source', 'builtin')}`")
            if b_def.get("extends"):
                print(f"**Extends:** {', '.join(b_def['extends'])}")
            if b_def.get("allow"):
                print("\n**Allow Rules:**")
                for r in b_def["allow"]:
                    print(f"- `{r}`")
            if b_def.get("ask"):
                print("\n**Ask Rules:**")
                for r in b_def["ask"]:
                    print(f"- `{r}`")
            if b_def.get("deny"):
                print("\n**Deny Rules:**")
                for r in b_def["deny"]:
                    print(f"- `{r}`")
            if b_def.get("custom_guidelines"):
                print("\n**Custom Guidelines:**")
                for g in b_def["custom_guidelines"]:
                    print(f"- {g}")
        sys.exit(0)

    # Dedicated standalone health-check mode
    if args.health_check:
        eff_config = resolve_classifier_config(
            session_dir=session_dir, workspace_paths=[workspace_dir]
        )
        provider = (args.provider or eff_config["provider"]).lower()
        if provider == "gemini":
            provider = "google"
        elif provider == "claude":
            provider = "anthropic"
        elif provider in ("sidecar", "worker"):
            provider = "antigravity"
        elif provider == "oauth":
            provider = "cloudcode"
        model = args.model or eff_config["model"]
        endpoint_url = args.endpoint_url or eff_config["endpoint_url"]
        api_key = args.api_key or eff_config["api_key"]

        is_healthy, status_msg, latency = probe_classifier_provider(
            provider=provider,
            model=model,
            endpoint_url=endpoint_url,
            api_key=api_key,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "healthy": is_healthy,
                        "provider": provider,
                        "model": model,
                        "endpoint_url": endpoint_url,
                        "message": status_msg,
                        "latency_ms": round(latency, 1),
                    },
                    indent=2,
                )
            )
        else:
            status_icon = "✅" if is_healthy else "❌"
            print(f"{status_icon} Provider Health Check ({provider} / {model}):")
            print(f"   Status: {status_msg}")
            print(f"   Latency: {latency:.1f}ms")
        sys.exit(0 if is_healthy else 1)

    actions_performed = []

    # 1. Update classifier settings if specified
    classifier_settings = {}
    if args.provider:
        p = args.provider.lower()
        if p == "gemini":
            p = "google"
        elif p == "claude":
            p = "anthropic"
        elif p in ("sidecar", "worker"):
            p = "antigravity"
        elif p == "oauth":
            p = "cloudcode"
        classifier_settings["provider"] = p
    if args.model:
        classifier_settings["model"] = args.model.strip()
    if args.endpoint_url:
        classifier_settings["endpoint_url"] = args.endpoint_url.strip()
    if args.api_key:
        classifier_settings["api_key"] = args.api_key.strip()
    if args.api_key_env:
        classifier_settings["api_key_env"] = args.api_key_env.strip()
    if args.timeout is not None:
        classifier_settings["timeout"] = float(args.timeout)

    if classifier_settings:
        # Pre-flight health probe if enabled
        if args.probe:
            eff_current = resolve_classifier_config(
                session_dir=session_dir, workspace_paths=[workspace_dir]
            )
            probe_prov = classifier_settings.get("provider", eff_current["provider"])
            probe_model = classifier_settings.get("model", eff_current["model"])
            probe_url = classifier_settings.get("endpoint_url", eff_current["endpoint_url"])
            probe_key = classifier_settings.get("api_key", eff_current["api_key"])

            is_healthy, status_msg, latency = probe_classifier_provider(
                provider=probe_prov,
                model=probe_model,
                endpoint_url=probe_url,
                api_key=probe_key,
            )
            if is_healthy:
                actions_performed.append(
                    f"Pre-flight health check passed ({probe_prov} / {probe_model}, "
                    f"{latency:.1f}ms)"
                )
            else:
                actions_performed.append(f"⚠️ Pre-flight health check warning: {status_msg}")

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

    # 7. Update Bundles (enable/disable)
    if args.enable_bundles or args.disable_bundles:
        target_file = update_bundles_in_scope(
            enabled_bundles=args.enable_bundles,
            disabled_bundles=args.disable_bundles,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        if args.enable_bundles:
            actions_performed.append(
                f"Enabled bundles {args.enable_bundles} in {scope} ({target_file})"
            )
        if args.disable_bundles:
            actions_performed.append(
                f"Disabled bundles {args.disable_bundles} in {scope} ({target_file})"
            )

    # 8. Update Governed Surfaces (opt-in subagents, schedule, images)
    governed_updates = {}
    if args.govern_subagents:
        governed_updates["subagents"] = True
    elif args.no_govern_subagents:
        governed_updates["subagents"] = False

    if args.govern_schedule:
        governed_updates["schedule"] = True
    elif args.no_govern_schedule:
        governed_updates["schedule"] = False

    if args.govern_images:
        governed_updates["images"] = True
    elif args.no_govern_images:
        governed_updates["images"] = False

    if governed_updates:
        target_file = update_governed_surfaces_in_scope(
            governed=governed_updates,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        actions_performed.append(f"Updated governed surfaces in {scope} ({target_file})")

    # 9. Update trust_workspace_writes setting
    if args.trust_workspace_writes is not None:
        target_file = update_trust_workspace_writes_setting(
            enabled=args.trust_workspace_writes,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        status_word = "enabled" if args.trust_workspace_writes else "disabled"
        actions_performed.append(
            f"{status_word.capitalize()} trust_workspace_writes in {scope} ({target_file})"
        )

    # 10. Update show_turn_summary setting
    if args.show_turn_summary is not None:
        target_file = update_show_turn_summary_setting(
            enabled=args.show_turn_summary,
            scope=scope,
            workspace_dir=workspace_dir,
            session_dir=session_dir,
        )
        status_word = "enabled" if args.show_turn_summary else "disabled"
        actions_performed.append(
            f"{status_word.capitalize()} show_turn_summary in {scope} ({target_file})"
        )

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
