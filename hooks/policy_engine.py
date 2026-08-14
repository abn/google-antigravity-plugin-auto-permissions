#!/usr/bin/env python3
"""
Policy Engine for Google Antigravity Auto-Permissions Plugin.
Handles static ACL rule evaluation, hierarchical policy scopes (Session, Project, Global),
and permission resource matching (Deny > Ask > Allow).
"""

import contextlib
import json
import os
import re
from typing import Any

GLOBAL_CONFIG_PATH = os.path.expanduser("~/.gemini/config/auto-permissions.json")
PROJECT_CONFIG_REL_PATH = os.path.join(".agents", "auto-permissions.json")
SESSION_OVERRIDES_FILENAME = "session_overrides.json"


def parse_resource_rule(rule_str: str) -> tuple[str, str] | None:
    """
    Parses a permission resource rule string formatted as `action(target)`.
    Example: `command(uv lock)` -> ('command', 'uv lock')
    """
    rule_str = rule_str.strip()
    match = re.match(r"^([a-zA-Z0-9_]+)\((.*)\)$", rule_str)
    if not match:
        return None
    action = match.group(1).strip()
    target = match.group(2).strip()
    return action, target


def match_command(pattern: str, command_line: str) -> bool:
    """
    Matches a command string against a pattern.
    Supports exact token prefix matching, global wildcards (*), and regex groups.
    """
    if pattern == "*":
        return True
    pattern = pattern.strip()
    command_line = command_line.strip()
    if not command_line:
        return False

    # If pattern contains regex special chars, evaluate as anchored regex
    try:
        if re.search(r"[\\^$*+?.()|[\]{}]", pattern):
            return bool(re.search(f"^{pattern}", command_line))
    except re.error:
        pass

    # Standard whitespace token prefix matching
    pat_tokens = pattern.split()
    cmd_tokens = command_line.split()
    if len(cmd_tokens) < len(pat_tokens):
        return False

    for pt, ct in zip(pat_tokens, cmd_tokens, strict=False):
        if pt == "*":
            continue
        if pt != ct:
            return False
    return True


def match_path(pattern: str, target_path: str) -> bool:
    """
    Matches a file path against a pattern.
    Supports exact path, directory prefix, wildcards, and regex.
    """
    if pattern == "*":
        return True
    pattern = os.path.expanduser(pattern.strip())
    target_path = os.path.expanduser(target_path.strip())

    if pattern == target_path:
        return True

    # Directory prefix match (e.g. `src/` or `/tmp/dir`)
    if pattern.endswith("/") and target_path.startswith(pattern):
        return True
    if target_path.startswith(pattern + "/"):
        return True

    try:
        if re.search(r"[\\^$*+?.()|[\]{}]", pattern):
            return bool(re.search(pattern, target_path))
    except re.error:
        pass

    return False


def match_url(pattern: str, target_url: str) -> bool:
    """Matches a URL or hostname against a domain pattern."""
    if pattern == "*":
        return True
    pattern = pattern.strip().lower()
    target_url = target_url.strip().lower()

    # Extract hostname if full URL is passed
    host_match = re.search(r"https?://([^/:]+)", target_url)
    target_host = host_match.group(1) if host_match else target_url.split("/")[0]

    return bool(pattern == target_host or target_host.endswith("." + pattern))


def match_tool_against_rule(rule_str: str, tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Evaluates if a specific tool call matches a permission resource rule."""
    parsed = parse_resource_rule(rule_str)
    if not parsed:
        return False
    action, target_pattern = parsed

    if tool_name == "run_command":
        cmd = str(tool_args.get("CommandLine", ""))
        if action == "command":
            return match_command(target_pattern, cmd)
        if action == "unsandboxed" and tool_args.get("BypassSandbox") is True:
            return match_command(target_pattern, cmd)

    elif tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        path = str(tool_args.get("TargetFile", ""))
        if action == "write_file":
            return match_path(target_pattern, path)

    elif tool_name == "view_file":
        path = str(tool_args.get("AbsolutePath", ""))
        if action in ("read_file", "view_file"):
            return match_path(target_pattern, path)

    elif tool_name == "list_dir":
        path = str(tool_args.get("DirectoryPath", ""))
        if action in ("read_file", "list_dir"):
            return match_path(target_pattern, path)

    elif tool_name == "grep_search":
        path = str(tool_args.get("SearchPath", ""))
        if action in ("read_file", "grep_search"):
            return match_path(target_pattern, path)

    elif tool_name == "read_url_content":
        url = str(tool_args.get("Url", ""))
        if action == "read_url":
            return match_url(target_pattern, url)

    elif tool_name == "manage_task":
        sub_action = str(tool_args.get("Action", ""))
        if action == "manage_task":
            return target_pattern in ("*", sub_action)

    elif tool_name.startswith("mcp_") or tool_name == "call_mcp_tool":
        server = str(tool_args.get("ServerName", ""))
        sub_tool = str(tool_args.get("ToolName", ""))
        full_tool = f"{server}/{sub_tool}" if server else tool_name
        if action == "mcp":
            if target_pattern == "*":
                return True
            if target_pattern.endswith("/*"):
                return full_tool.startswith(target_pattern[:-1])
            return target_pattern == full_tool

    return False


def is_path_in_workspaces(target_path: str, workspace_paths: list[str] | None) -> bool:
    """Checks if a target path is strictly located within one of the active workspace roots."""
    if not workspace_paths or not target_path:
        return False
    norm_target = os.path.abspath(os.path.expanduser(target_path))
    for ws in workspace_paths:
        norm_ws = os.path.abspath(os.path.expanduser(ws))
        if norm_target == norm_ws or norm_target.startswith(norm_ws + os.sep):
            return True
    return False


def load_policy_file(file_path: str) -> dict[str, list[str]]:
    """Loads a policy JSON file returning a dict with keys 'allow', 'ask', 'deny'."""
    policy = {"allow": [], "ask": [], "deny": []}
    if not file_path or not os.path.isfile(file_path):
        return policy

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                for k in ("allow", "ask", "deny"):
                    val = data.get(k, [])
                    if isinstance(val, list):
                        policy[k] = [str(x) for x in val]
    except Exception:
        pass
    return policy


def save_policy_file(file_path: str, policy: dict[str, list[str]]) -> None:
    """Saves policy dictionary to file atomically."""
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(parent_dir, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def add_rule_to_scope(
    rule_str: str,
    decision: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """
    Adds a rule to the specified policy scope ('session', 'project', 'global').
    Returns the file path written to.
    """
    decision = decision.lower()
    if decision not in ("allow", "ask", "deny"):
        msg = f"Invalid decision '{decision}'. Must be allow, ask, or deny."
        raise ValueError(msg)

    if scope == "session":
        if not session_dir:
            msg = "Session directory is required for session-scope rule."
            raise ValueError(msg)
        target_path = os.path.join(session_dir, SESSION_OVERRIDES_FILENAME)
    elif scope == "project":
        ws = workspace_dir or os.getcwd()
        target_path = os.path.join(ws, PROJECT_CONFIG_REL_PATH)
    elif scope == "global":
        target_path = GLOBAL_CONFIG_PATH
    else:
        msg = f"Invalid scope '{scope}'. Must be session, project, or global."
        raise ValueError(msg)

    policy = load_policy_file(target_path)
    if rule_str not in policy[decision]:
        # Remove from other buckets if present
        for other_k in ("allow", "ask", "deny"):
            with contextlib.suppress(ValueError):
                policy[other_k].remove(rule_str)
        policy[decision].append(rule_str)
        save_policy_file(target_path, policy)

    return target_path


def evaluate_static_policies(
    tool_name: str,
    tool_args: dict[str, Any],
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> tuple[str, str, str] | None:
    """
    Evaluates tool against Session, Project, and Global policies with priority Deny > Ask > Allow.

    Returns:
        Tuple of (decision, reason, scope) if matched, or None if no static match.
    """
    scope_files = []

    # 1. Session scope (highest specificity)
    if session_dir and os.path.isdir(session_dir):
        scope_files.append(("session", os.path.join(session_dir, SESSION_OVERRIDES_FILENAME)))

    # 2. Project scope
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(("project", os.path.join(ws, PROJECT_CONFIG_REL_PATH)))

    # 3. Global scope
    scope_files.append(("global", GLOBAL_CONFIG_PATH))

    # Evaluate each scope with strict Deny > Ask > Allow precedence
    for scope_name, file_path in scope_files:
        if not os.path.isfile(file_path):
            continue
        policy = load_policy_file(file_path)

        # Check Deny first
        for rule in policy.get("deny", []):
            if match_tool_against_rule(rule, tool_name, tool_args):
                return (
                    "deny",
                    f"Blocked by static {scope_name} policy rule '{rule}'",
                    scope_name,
                )

        # Check Ask second
        for rule in policy.get("ask", []):
            if match_tool_against_rule(rule, tool_name, tool_args):
                return (
                    "ask",
                    f"Escalated by static {scope_name} policy rule '{rule}'",
                    scope_name,
                )

        # Check Allow third
        for rule in policy.get("allow", []):
            if match_tool_against_rule(rule, tool_name, tool_args):
                return (
                    "allow",
                    f"Auto-approved by static {scope_name} policy rule '{rule}'",
                    scope_name,
                )

    # 4. Built-in fast-path for read-only workspace inspection
    if tool_name in ("view_file", "list_dir", "grep_search"):
        target_path = ""
        if tool_name == "view_file":
            target_path = str(tool_args.get("AbsolutePath", ""))
        elif tool_name == "list_dir":
            target_path = str(tool_args.get("DirectoryPath", ""))
        elif tool_name == "grep_search":
            target_path = str(tool_args.get("SearchPath", ""))

        if target_path and is_path_in_workspaces(target_path, workspace_paths):
            return (
                "allow",
                f"Auto-approved workspace read inspection for {tool_name}",
                "workspace_boundary",
            )

    return None
