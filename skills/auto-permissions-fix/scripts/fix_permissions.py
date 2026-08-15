#!/usr/bin/env python3
"""
CLI helper to generate and apply Antigravity permission rules from audit.jsonl denials.
Supports configuring static rules at Session, Project, or Global scopes.
"""

import argparse
import json
import os
import re
import sys
from typing import Any

# Ensure hooks package is importable
current_dir = os.path.dirname(os.path.abspath(__file__))
plugin_root = os.path.abspath(os.path.join(current_dir, "../../.."))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from hooks.policy_engine import (  # noqa: E402
    GLOBAL_CONFIG_PATH,
    PROJECT_CONFIG_REL_PATH,
    add_rule_to_scope,
)


def suggest_rules_for_tool_call(tool_name: str, tool_args: dict[str, Any]) -> list[str]:
    """Derives candidate Antigravity permission rule strings from a tool call."""
    suggestions = []

    if tool_name == "run_command":
        cmd = str(tool_args.get("CommandLine", "")).strip()
        if cmd:
            tokens = cmd.split()
            # 1. Exact command
            suggestions.append(f"command({cmd})")
            # 2. Binary + Subcommand prefix (e.g. `uv lock`, `git status`)
            if len(tokens) >= 2 and not tokens[0].startswith("-"):
                suggestions.append(f"command({tokens[0]} {tokens[1]})")
            # 3. Binary only prefix (e.g. `pytest`, `ruff`)
            if len(tokens) >= 1:
                suggestions.append(f"command({tokens[0]})")
            # 4. Unsandboxed variant if requested
            if tool_args.get("BypassSandbox") is True:
                suggestions.append(f"unsandboxed({cmd})")
                if len(tokens) >= 2:
                    suggestions.append(f"unsandboxed({tokens[0]} {tokens[1]})")

    elif tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        path = str(tool_args.get("TargetFile", "")).strip()
        if path:
            suggestions.append(f"write_file({path})")
            parent = os.path.dirname(path)
            if parent:
                suggestions.append(f"write_file({parent}/.*)")

    elif tool_name == "read_url_content":
        url = str(tool_args.get("Url", "")).strip()
        if url:
            host_match = re.search(r"https?://([^/:]+)", url)
            host = host_match.group(1) if host_match else url.split("/")[0]
            suggestions.append(f"read_url({host})")

    elif tool_name == "manage_task":
        action = str(tool_args.get("Action", "")).strip()
        if action:
            suggestions.append(f"manage_task({action})")

    elif tool_name == "call_mcp_tool":
        server = str(tool_args.get("ServerName", "")).strip()
        sub_tool = str(tool_args.get("ToolName", "")).strip()
        if server and sub_tool:
            suggestions.append(f"mcp({server}:{sub_tool})")
            suggestions.append(f"mcp({server}:*)")
        elif server:
            suggestions.append(f"mcp({server}:*)")

    elif tool_name.startswith("mcp_"):
        raw = tool_name[4:]
        if "_" in raw:
            server, sub_tool = raw.split("_", 1)
            suggestions.append(f"mcp({server}:{sub_tool})")
            suggestions.append(f"mcp({server}:*)")
        else:
            suggestions.append(f"mcp({raw}:*)")

    elif tool_name in ("read_resource", "list_resources"):
        server = str(tool_args.get("ServerName", "")).strip()
        if server:
            suggestions.append(f"mcp({server}:{tool_name})")
            suggestions.append(f"mcp({server}:*)")

    return list(dict.fromkeys(suggestions))  # Deduplicate preserving order


def load_denied_audit_records(audit_path: str) -> list[dict[str, Any]]:
    """Loads all records from audit.jsonl with decision DENY or ASK."""
    if not audit_path or not os.path.isfile(audit_path):
        return []

    denials = []
    with open(audit_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                decision = (
                    record.get("hook_output", {}).get("decision")
                    or record.get("classification", {}).get("decision", "")
                ).lower()
                if decision in ("deny", "ask", "force_ask"):
                    denials.append(record)
            except json.JSONDecodeError:
                continue
    return denials


def find_default_audit_log() -> str | None:
    """Finds the active session's audit log file if available."""
    # Check current directory
    if os.path.isfile("./auto-permissions/audit.jsonl"):
        return os.path.abspath("./auto-permissions/audit.jsonl")
    if os.path.isfile("./audit.jsonl"):
        return os.path.abspath("./audit.jsonl")

    # Search ~/.gemini/antigravity/brain/*/audit.jsonl
    # or */auto-permissions/audit.jsonl for most recent
    brain_dir = os.path.expanduser("~/.gemini/antigravity/brain")
    if os.path.isdir(brain_dir):
        candidates = []
        for root, _dirs, files in os.walk(brain_dir):
            if "audit.jsonl" in files:
                fpath = os.path.join(root, "audit.jsonl")
                candidates.append((os.path.getmtime(fpath), fpath))
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
    return None


def run_interactive(denials: list[dict[str, Any]], session_dir: str | None) -> None:
    """Runs interactive CLI selector for audit denials."""
    total = len(denials)
    print("=" * 80)
    print(f"AUTO-PERMISSIONS FIX (Found {total} Denials/Escalations in Audit Log)")
    print("=" * 80)

    for i, r in enumerate(denials[-10:], 1):
        ts = r.get("timestamp", "")
        tool = r.get("toolCall", {}).get("name", "")
        args = r.get("toolCall", {}).get("args", {})
        cmd = args.get("CommandLine") or args.get("TargetFile") or json.dumps(args)[:60]
        decision = r.get("hook_output", {}).get("decision", "").upper()
        reason = r.get("hook_output", {}).get("reason", "")
        rules = suggest_rules_for_tool_call(tool, args)
        suggested = rules[0] if rules else "N/A"

        print(f"[{i}] {ts} | {decision:<6} | Tool: {tool}")
        print(f"    Target: {cmd}")
        print(f"    Reason: {reason}")
        print(f"    Suggested Rule: {suggested}")
        print()

    print("-" * 80)
    choice_str = input("Select record number to generate rule for (or 'q' to quit): ").strip()
    if choice_str.lower() in ("q", "quit", ""):
        print("Aborted.")
        return

    try:
        idx = int(choice_str)
        selected_record = denials[-10:][idx - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    tool = selected_record.get("toolCall", {}).get("name", "")
    args = selected_record.get("toolCall", {}).get("args", {})
    rules = suggest_rules_for_tool_call(tool, args)
    if not rules:
        print("No automatic rule could be derived.")
        return

    print("\nCandidate Rules:")
    for r_idx, r_str in enumerate(rules, 1):
        print(f"  ({r_idx}) {r_str}")
    r_choice = input(f"Select rule [1-{len(rules)}] (default 1): ").strip()
    selected_rule = (
        rules[int(r_choice) - 1]
        if r_choice.isdigit() and 1 <= int(r_choice) <= len(rules)
        else rules[0]
    )

    print("\nTarget Policy Scope:")
    print("  (1) Session Scope (Active session only)")
    print(f"  (2) Project Scope ({PROJECT_CONFIG_REL_PATH})")
    print(f"  (3) Global Scope ({GLOBAL_CONFIG_PATH})")
    s_choice = input("Select scope [1-3] (default 2): ").strip()
    scope_map = {"1": "session", "2": "project", "3": "global"}
    selected_scope = scope_map.get(s_choice, "project")

    print("\nPolicy Decision:")
    print("  (1) Allow (Auto-approve with 0ms latency)")
    print("  (2) Ask (Always prompt human)")
    print("  (3) Deny (Hard block with 0ms latency)")
    d_choice = input("Select decision [1-3] (default 1): ").strip()
    decision_map = {"1": "allow", "2": "ask", "3": "deny"}
    selected_decision = decision_map.get(d_choice, "allow")

    out_file = add_rule_to_scope(
        rule_str=selected_rule,
        decision=selected_decision,
        scope=selected_scope,
        workspace_dir=os.getcwd(),
        session_dir=session_dir,
    )
    print(f"\nSuccessfully added '{selected_rule}' -> {selected_decision.upper()} in {out_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Auto-Permissions Fix: Generate and apply ACL rules from audit denials."
    )
    parser.add_argument("--audit-log", "-i", help="Path to audit.jsonl file.")
    parser.add_argument("--last", action="store_true", help="Target the most recent denied record.")
    parser.add_argument("--index", type=int, help="Target specific 1-based index from recent list.")
    parser.add_argument(
        "--scope",
        choices=["session", "project", "global"],
        default="project",
        help="Target policy scope (default: project).",
    )
    parser.add_argument(
        "--decision",
        choices=["allow", "ask", "deny"],
        default=None,
        help="Policy decision to assign (default: allow).",
    )
    parser.add_argument("--allow", action="store_true", help="Set decision to allow.")
    parser.add_argument("--ask", action="store_true", help="Set decision to ask.")
    parser.add_argument("--deny", action="store_true", help="Set decision to deny.")
    parser.add_argument("--rule", help="Custom permission rule override string.")

    args = parser.parse_args()

    # Resolve decision flag
    decision = args.decision or "allow"
    if args.deny:
        decision = "deny"
    elif args.ask:
        decision = "ask"
    elif args.allow:
        decision = "allow"

    if args.rule:
        audit_path = args.audit_log or find_default_audit_log()
        session_dir = os.path.dirname(os.path.abspath(audit_path)) if audit_path else None
        out_file = add_rule_to_scope(
            rule_str=args.rule,
            decision=decision,
            scope=args.scope,
            workspace_dir=os.getcwd(),
            session_dir=session_dir,
        )
        print(f"Applied rule: '{args.rule}' -> {decision.upper()} [{args.scope}] in {out_file}")
        return

    audit_path = args.audit_log or find_default_audit_log()
    if not audit_path or not os.path.isfile(audit_path):
        print("Error: No audit.jsonl log file found. Specify path via --audit-log <path>.")
        sys.exit(1)

    session_dir = os.path.dirname(os.path.abspath(audit_path))
    denials = load_denied_audit_records(audit_path)
    if not denials:
        print(f"No denied or escalated records found in audit log: {audit_path}")
        return

    if args.last or args.index:
        idx = -1 if args.last else (args.index - 1)
        try:
            target_record = denials[idx]
        except IndexError:
            print(f"Error: Index {args.index} out of range (Total denials: {len(denials)}).")
            sys.exit(1)

        tool = target_record.get("toolCall", {}).get("name", "")
        tool_args = target_record.get("toolCall", {}).get("args", {})
        rule_to_apply = args.rule
        if not rule_to_apply:
            suggestions = suggest_rules_for_tool_call(tool, tool_args)
            if not suggestions:
                print(f"Error: Could not derive a rule for tool '{tool}'. Use --rule to specify.")
                sys.exit(1)
            rule_to_apply = suggestions[0]

        out_file = add_rule_to_scope(
            rule_str=rule_to_apply,
            decision=decision,
            scope=args.scope,
            workspace_dir=os.getcwd(),
            session_dir=session_dir,
        )
        print(f"Applied rule: '{rule_to_apply}' -> {decision.upper()} [{args.scope}] in {out_file}")
    else:
        run_interactive(denials, session_dir)


if __name__ == "__main__":
    main()
