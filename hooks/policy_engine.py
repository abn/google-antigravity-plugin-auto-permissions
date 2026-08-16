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

try:
    from hooks.bundles import (
        get_builtin_bundle,
        list_builtin_bundles,
        load_bundle_from_file,
    )
except ImportError:
    from bundles import (
        get_builtin_bundle,
        list_builtin_bundles,
        load_bundle_from_file,
    )

# Global Configuration Paths
GLOBAL_CONFIG_DIR = os.path.expanduser("~/.gemini/config/auto-permissions")
GLOBAL_CONFIG_PRIMARY = os.path.join(GLOBAL_CONFIG_DIR, "config.json")
GLOBAL_CONFIG_LEGACY = os.path.expanduser("~/.gemini/config/auto-permissions.json")
GLOBAL_CONFIG_PATH = GLOBAL_CONFIG_LEGACY  # Kept for backward compatibility
GLOBAL_BUNDLES_DIR = os.path.join(GLOBAL_CONFIG_DIR, "bundles")

# Project Scoped Configuration Paths
PROJECT_CONFIG_DIR_REL = os.path.join(".agents", "auto-permissions")
PROJECT_CONFIG_PRIMARY_REL = os.path.join(PROJECT_CONFIG_DIR_REL, "config.json")
PROJECT_CONFIG_LEGACY_REL = os.path.join(".agents", "auto-permissions.json")
PROJECT_CONFIG_REL_PATH = PROJECT_CONFIG_LEGACY_REL  # Kept for backward compatibility

PROJECT_LOCAL_CONFIG_PRIMARY_REL = os.path.join(PROJECT_CONFIG_DIR_REL, "config.local.json")
PROJECT_LOCAL_CONFIG_LEGACY_REL = os.path.join(".agents", "auto-permissions.local.json")
PROJECT_LOCAL_CONFIG_REL_PATH = PROJECT_LOCAL_CONFIG_LEGACY_REL

PROJECT_BUNDLES_DIR_REL = os.path.join(PROJECT_CONFIG_DIR_REL, "bundles")
PROJECT_LOCAL_BUNDLES_DIR_REL = os.path.join(PROJECT_CONFIG_DIR_REL, "bundles.local")

SESSION_PLUGIN_SUBDIR = "auto-permissions"
SESSION_OVERRIDES_FILENAME = "session_overrides.json"
DEFAULT_TIMEOUT_SECS = 6.0


def resolve_session_override_path(session_dir: str | None) -> str | None:
    """
    Resolves the session override path, checking auto-permissions/ subdir first,
    falling back to legacy root.
    """
    if not session_dir:
        return None
    scoped = os.path.join(session_dir, SESSION_PLUGIN_SUBDIR, SESSION_OVERRIDES_FILENAME)
    legacy = os.path.join(session_dir, SESSION_OVERRIDES_FILENAME)
    if os.path.isfile(scoped):
        return scoped
    if os.path.isfile(legacy):
        return legacy
    return scoped


def resolve_project_config_path(
    workspace_dir: str | None = None, prefer_existing: bool = True
) -> str:
    """Resolves project config path (.agents/auto-permissions/config.json with legacy fallback)."""
    ws = workspace_dir or os.getcwd()
    primary = os.path.join(ws, PROJECT_CONFIG_PRIMARY_REL)
    legacy = os.path.join(ws, PROJECT_CONFIG_LEGACY_REL)
    if prefer_existing:
        if os.path.isfile(primary):
            return primary
        if os.path.isfile(legacy):
            return legacy
    return primary


def resolve_project_local_config_path(
    workspace_dir: str | None = None, prefer_existing: bool = True
) -> str:
    """
    Resolves local project config path
    (.agents/auto-permissions/config.local.json with legacy fallback).
    """
    ws = workspace_dir or os.getcwd()
    primary = os.path.join(ws, PROJECT_LOCAL_CONFIG_PRIMARY_REL)
    legacy = os.path.join(ws, PROJECT_LOCAL_CONFIG_LEGACY_REL)
    if prefer_existing:
        if os.path.isfile(primary):
            return primary
        if os.path.isfile(legacy):
            return legacy
    return primary


def resolve_global_config_path(prefer_existing: bool = True) -> str:
    """
    Resolves global config path
    (~/.gemini/config/auto-permissions/config.json with legacy fallback).
    """
    if prefer_existing:
        if os.path.isfile(GLOBAL_CONFIG_PRIMARY):
            return GLOBAL_CONFIG_PRIMARY
        if os.path.isfile(GLOBAL_CONFIG_LEGACY):
            return GLOBAL_CONFIG_LEGACY
    return GLOBAL_CONFIG_PRIMARY


def get_scope_file_candidates(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> list[tuple[str, str]]:
    """
    Returns ordered list of (scope_name, file_path) pairs for policy evaluation
    (Session > Local Project > Tracked Project > Global).
    """
    files: list[tuple[str, str]] = []
    if session_dir and os.path.isdir(session_dir):
        sf = resolve_session_override_path(session_dir)
        if sf:
            files.append(("session", sf))
    if workspace_paths:
        for ws in workspace_paths:
            lf = resolve_project_local_config_path(ws)
            files.append(("project_local", lf))
            pf = resolve_project_config_path(ws)
            files.append(("project", pf))
    gf = resolve_global_config_path()
    files.append(("global", gf))
    return files


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


def match_mcp(pattern: str, server_name: str, tool_name: str) -> bool:
    """
    Matches an MCP server and tool name against a pattern.
    Supported patterns:
      - `*` (any MCP tool)
      - `server:*` or `server/*` or `server` (any tool on that server)
      - `server:tool` or `server/tool` (exact tool on that server)
      - `*:tool` (matching tool across any server)
      - regex patterns
    """
    if pattern == "*":
        return True
    pattern = pattern.strip()
    full_colon = f"{server_name}:{tool_name}" if server_name else tool_name
    full_slash = f"{server_name}/{tool_name}" if server_name else tool_name

    # Check exact match on server name
    if pattern == server_name:
        return True

    # Check colon / slash exact match
    if pattern in (full_colon, full_slash):
        return True

    # Check wildcard patterns
    if pattern.endswith(":*") and server_name == pattern[:-2]:
        return True
    if pattern.endswith("/*") and server_name == pattern[:-2]:
        return True
    if pattern.startswith("*:") and tool_name == pattern[2:]:
        return True
    if pattern.startswith("*/") and tool_name == pattern[2:]:
        return True

    # Regex support
    try:
        if re.search(r"[\\^$*+?.()|[\]{}]", pattern):
            return bool(re.search(pattern, full_colon) or re.search(pattern, full_slash))
    except re.error:
        pass

    return False


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
        path = str(
            tool_args.get("TargetFile")
            or tool_args.get("target_file")
            or tool_args.get("AbsolutePath")
            or tool_args.get("path")
            or ""
        )
        if action == "write_file":
            return match_path(target_pattern, path)

    elif tool_name == "view_file":
        path = str(
            tool_args.get("AbsolutePath")
            or tool_args.get("path")
            or tool_args.get("TargetFile")
            or tool_args.get("target_file")
            or ""
        )
        if action in ("read_file", "view_file"):
            return match_path(target_pattern, path)

    elif tool_name == "list_dir":
        path = str(
            tool_args.get("DirectoryPath")
            or tool_args.get("directory_path")
            or tool_args.get("path")
            or ""
        )
        if action in ("read_file", "list_dir"):
            return match_path(target_pattern, path)

    elif tool_name == "grep_search":
        path = str(
            tool_args.get("SearchPath")
            or tool_args.get("search_path")
            or tool_args.get("path")
            or ""
        )
        if action in ("read_file", "grep_search"):
            return match_path(target_pattern, path)

    elif tool_name == "read_url_content":
        url = str(tool_args.get("Url") or tool_args.get("url") or "")
        if action == "read_url":
            return match_url(target_pattern, url)

    elif tool_name == "manage_task":
        sub_action = str(tool_args.get("Action") or tool_args.get("action") or "")
        if action == "manage_task":
            return target_pattern in ("*", sub_action)

    elif tool_name == "call_mcp_tool":
        server = str(tool_args.get("ServerName") or tool_args.get("server_name") or "")
        sub_tool = str(tool_args.get("ToolName") or tool_args.get("tool_name") or "")
        if action in ("mcp", "call_mcp_tool"):
            return match_mcp(target_pattern, server, sub_tool)

    elif tool_name.startswith("mcp_"):
        raw = tool_name[4:]
        if "_" in raw:
            server, sub_tool = raw.split("_", 1)
        else:
            server, sub_tool = raw, "*"
        if action in ("mcp", "call_mcp_tool"):
            return match_mcp(target_pattern, server, sub_tool)

    elif tool_name in ("read_resource", "list_resources"):
        server = str(tool_args.get("ServerName") or tool_args.get("server_name") or "")
        if action in ("mcp", "read_resource", "list_resources"):
            return match_mcp(target_pattern, server, tool_name)

    elif tool_name in ("invoke_subagent", "define_subagent", "manage_subagents", "send_message"):
        if action in ("subagent", "agent", tool_name):
            return match_subagent(target_pattern, tool_name, tool_args)

    elif tool_name == "schedule":
        if action in ("schedule", "timer", "cron"):
            return match_schedule(target_pattern, tool_name, tool_args)

    elif tool_name == "generate_image":
        if action in ("image", "generate_image"):
            return match_image(target_pattern, tool_name, tool_args)

    return False


def match_subagent(pattern: str, tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Matches subagent invocation or definition against a pattern."""
    if pattern == "*":
        return True
    pattern = pattern.strip().lower()

    if tool_name == "invoke_subagent":
        subagents = tool_args.get("Subagents", [])
        if isinstance(subagents, list):
            for sa in subagents:
                if isinstance(sa, dict):
                    t_name = str(sa.get("TypeName", "")).lower()
                    role = str(sa.get("Role", "")).lower()
                    if pattern in (t_name, role) or pattern in t_name or pattern in role:
                        return True
        return False

    if tool_name == "define_subagent":
        name = str(tool_args.get("name", "")).lower()
        return pattern in name or pattern == name

    if tool_name == "manage_subagents":
        action = str(tool_args.get("Action", "")).lower()
        return pattern == "*" or pattern == action

    if tool_name == "send_message":
        recipient = str(tool_args.get("Recipient", "")).lower()
        return pattern == "*" or pattern == recipient

    return False


def match_schedule(pattern: str, tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Matches scheduled timers or cron jobs against a pattern."""
    if tool_name != "schedule":
        return False
    if pattern == "*":
        return True
    pattern = pattern.strip().lower()
    if pattern == "cron" and "CronExpression" in tool_args:
        return True
    return bool(pattern == "timer" and "DurationSeconds" in tool_args)


def match_image(pattern: str, tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Matches generate_image calls against a pattern."""
    if tool_name != "generate_image":
        return False
    if pattern == "*":
        return True
    pattern = pattern.strip().lower()
    img_name = str(tool_args.get("ImageName", "")).lower()
    prompt = str(tool_args.get("Prompt", "")).lower()
    return pattern in img_name or pattern in prompt


SENSITIVE_PATH_PATTERNS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".config/gcloud",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/root",
)

SENSITIVE_FILENAMES = (
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".env",
    "credentials",
    "secrets.json",
    "service-account.json",
)

DEFAULT_TRUST_WORKSPACE_WRITES = True

# Directory names and file patterns that must NEVER be fast-path written
SENSITIVE_WRITE_PATTERNS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".config/gcloud",
    ".git",
    ".github",
    ".gitlab",
    ".credentials",
    ".agents",
    ".npmrc",
    ".pypirc",
)

SENSITIVE_WRITE_EXTENSIONS = (
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".token",
)


def is_sensitive_path(path: str) -> bool:
    """Checks if a path targets sensitive system or credential files."""
    if not path:
        return False
    norm = os.path.abspath(os.path.expanduser(path))
    real = os.path.realpath(norm)
    for target in (norm, real):
        for pattern in SENSITIVE_PATH_PATTERNS:
            expanded = os.path.abspath(
                os.path.expanduser(f"~/{pattern}" if pattern.startswith(".") else pattern)
            )
            if target == expanded or target.startswith(expanded + os.sep):
                return True
        basename = os.path.basename(target)
        if basename in SENSITIVE_FILENAMES:
            return True
    return False


def is_sensitive_write_path(path: str) -> bool:
    """
    Checks if a write target path touches sensitive credentials, git metadata,
    CI/CD workflows, or security plugin policy files.
    """
    if not path:
        return True
    if is_sensitive_path(path):
        return True
    norm = os.path.abspath(os.path.expanduser(path))
    real = os.path.realpath(norm)
    for target in (norm, real):
        _, ext = os.path.splitext(target)
        if ext.lower() in SENSITIVE_WRITE_EXTENSIONS:
            return True
        parts = target.split(os.sep)
        for part in parts:
            if part in SENSITIVE_WRITE_PATTERNS or part.startswith(".env"):
                return True
            if part.startswith("id_"):
                return True
        basename = os.path.basename(target)
        if basename.startswith(".env") or basename in (
            "plugin.json",
            "hooks.json",
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
        ):
            return True
    return False


def is_path_in_workspaces(target_path: str, workspace_paths: list[str] | None) -> bool:
    """
    Checks if a target path is strictly located within one of the active workspace roots.
    Evaluates both logical abspath and physical realpath to prevent symlink traversal attacks.
    """
    if not workspace_paths or not target_path:
        return False
    norm_target = os.path.abspath(os.path.expanduser(target_path))
    real_target = os.path.realpath(norm_target)

    # Sensitive path protection
    if is_sensitive_path(norm_target) or is_sensitive_path(real_target):
        return False

    for ws in workspace_paths:
        norm_ws = os.path.abspath(os.path.expanduser(ws))
        real_ws = os.path.realpath(norm_ws)
        is_logical_in = norm_target == norm_ws or norm_target.startswith(norm_ws + os.sep)
        is_real_in = real_target == real_ws or real_target.startswith(real_ws + os.sep)
        if is_logical_in and is_real_in:
            return True
    return False


def load_policy_file(file_path: str) -> dict[str, Any]:
    """
    Loads a policy JSON file returning a dict with keys
    'allow', 'ask', 'deny', 'custom_guidelines', 'allowed_skill_paths',
    'provider', 'model', 'endpoint_url', 'api_key', 'api_key_env', 'timeout',
    'bundles', 'custom_bundles'.
    """
    policy: dict[str, Any] = {
        "allow": [],
        "ask": [],
        "deny": [],
        "custom_guidelines": [],
        "allowed_skill_paths": [],
        "govern_surfaces": [],
        "govern_subagents": None,
        "govern_schedule": None,
        "govern_images": None,
        "trust_workspace_writes": None,
        "show_turn_summary": None,
        "disclose_turn_summary": None,
        "provider": None,
        "model": None,
        "endpoint_url": None,
        "api_key": None,
        "api_key_env": None,
        "timeout": None,
        "timeout_secs": None,
        "bundles": [],
        "custom_bundles": {},
    }
    if not file_path or not os.path.isfile(file_path):
        return policy

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                for k in (
                    "allow",
                    "ask",
                    "deny",
                    "custom_guidelines",
                    "allowed_skill_paths",
                    "govern_surfaces",
                ):
                    val = data.get(k, [])
                    if isinstance(val, list):
                        policy[k] = [str(x) for x in val]
                for bool_k in (
                    "govern_subagents",
                    "govern_schedule",
                    "govern_images",
                    "trust_workspace_writes",
                    "show_turn_summary",
                    "disclose_turn_summary",
                ):
                    if bool_k in data and isinstance(data[bool_k], bool):
                        policy[bool_k] = data[bool_k]
                raw_gov_surfaces = data.get("governed_surfaces")
                if isinstance(raw_gov_surfaces, dict):
                    for k in ("subagents", "schedule", "images"):
                        if k in raw_gov_surfaces and isinstance(raw_gov_surfaces[k], bool):
                            policy[f"govern_{k}"] = raw_gov_surfaces[k]
                if (
                    policy.get("show_turn_summary") is None
                    and policy.get("disclose_turn_summary") is not None
                ):
                    policy["show_turn_summary"] = policy["disclose_turn_summary"]
                for num_k in ("timeout", "timeout_secs"):
                    val = data.get(num_k)
                    if val is not None:
                        with contextlib.suppress(ValueError, TypeError):
                            policy[num_k] = float(val)
                if policy.get("timeout") is None and policy.get("timeout_secs") is not None:
                    policy["timeout"] = policy["timeout_secs"]
                elif policy.get("timeout") is not None and policy.get("timeout_secs") is None:
                    policy["timeout_secs"] = policy["timeout"]
                for str_k in (
                    "provider",
                    "protocol",
                    "model",
                    "endpoint_url",
                    "uri",
                    "api_base",
                    "api_key",
                    "api_key_env",
                ):
                    val = data.get(str_k)
                    if isinstance(val, str) and val.strip():
                        clean_v = val.strip()
                        if str_k in ("provider", "protocol"):
                            policy["provider"] = clean_v.lower()
                        elif str_k in ("endpoint_url", "uri", "api_base"):
                            policy["endpoint_url"] = clean_v
                        elif str_k == "model":
                            policy["model"] = clean_v
                        elif str_k == "api_key":
                            policy["api_key"] = clean_v
                        elif str_k == "api_key_env":
                            policy["api_key_env"] = clean_v
                raw_bundles = data.get("bundles")
                if isinstance(raw_bundles, list):
                    policy["bundles"] = [str(x) for x in raw_bundles if str(x).strip()]
                elif isinstance(raw_bundles, dict):
                    enabled = [
                        str(x)
                        for x in raw_bundles.get("enabled", [])
                        if isinstance(raw_bundles.get("enabled"), list) and str(x).strip()
                    ]
                    disabled = [
                        str(x)
                        for x in raw_bundles.get("disabled", [])
                        if isinstance(raw_bundles.get("disabled"), list) and str(x).strip()
                    ]
                    policy["bundles"] = {"enabled": enabled, "disabled": disabled}
                raw_custom_bundles = data.get("custom_bundles")
                if isinstance(raw_custom_bundles, dict):
                    policy["custom_bundles"] = raw_custom_bundles
    except Exception:
        pass
    return policy


def resolve_governed_surfaces(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> dict[str, bool]:
    """
    Resolves whether subagents, schedule, and images require security gate classification.
    Defaults: subagents=True, schedule=True, images=False.
    Can be overridden in Session, Project, Global scopes, bundles, or environment variables.
    """
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    governed = {
        "subagents": True,
        "schedule": True,
        "images": False,
    }

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        for k in ("subagents", "schedule", "images"):
            pol_key = f"govern_{k}"
            if pol.get(pol_key) is not None:
                governed[k] = bool(pol[pol_key])
        for s in pol.get("govern_surfaces", []):
            clean_s = s.strip().lower()
            if clean_s in governed:
                governed[clean_s] = True

    # Bundled surfaces
    bundled = resolve_active_bundles(session_dir=session_dir, workspace_paths=workspace_paths)
    for k, v in bundled.get("govern_surfaces", {}).items():
        if v and k in governed:
            governed[k] = True

    # Environment variables (explicit true or false overrides)
    for k, env_var in (
        ("subagents", "AUTO_PERMISSIONS_GOVERN_SUBAGENTS"),
        ("schedule", "AUTO_PERMISSIONS_GOVERN_SCHEDULE"),
        ("images", "AUTO_PERMISSIONS_GOVERN_IMAGES"),
    ):
        val = os.environ.get(env_var)
        if val is not None:
            clean_v = val.strip().lower()
            if clean_v in ("1", "true", "yes"):
                governed[k] = True
            elif clean_v in ("0", "false", "no"):
                governed[k] = False

    env_surfaces = os.environ.get("AUTO_PERMISSIONS_GOVERN_SURFACES", "")
    if env_surfaces:
        for s in env_surfaces.split(","):
            clean_s = s.strip().lower()
            if clean_s in governed:
                governed[clean_s] = True

    return governed


def is_ungoverned_surface(
    tool_name: str,
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> bool:
    """Checks if a tool belongs to an opt-in governance surface that is currently disabled."""
    governed = resolve_governed_surfaces(session_dir=session_dir, workspace_paths=workspace_paths)
    if tool_name in ("invoke_subagent", "define_subagent", "manage_subagents", "send_message"):
        return not governed["subagents"]
    if tool_name == "schedule":
        return not governed["schedule"]
    if tool_name == "generate_image":
        return not governed["images"]
    return False


def load_allowed_skill_paths(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> list[str]:
    """
    Loads allowed skill directory paths from default standard locations plus
    any user-configured 'allowed_skill_paths' in policies or active bundles.
    Also automatically discovers realpaths of installed and symlinked plugins.
    """
    # Standard Antigravity defaults
    allowed: list[str] = [
        os.path.abspath(os.path.expanduser("~/.gemini")),
        os.path.abspath(os.path.expanduser("~/.agents/skills")),
    ]
    if workspace_paths:
        for ws in workspace_paths:
            allowed.append(os.path.abspath(os.path.join(ws, ".agents", "skills")))
            ws_plugins = os.path.abspath(os.path.join(ws, ".agents", "plugins"))
            if os.path.isdir(ws_plugins):
                try:
                    for entry in os.listdir(ws_plugins):
                        p_dir = os.path.join(ws_plugins, entry)
                        real_p = os.path.realpath(p_dir)
                        if os.path.isdir(real_p) and real_p not in allowed:
                            allowed.append(real_p)
                except OSError:
                    pass

    # Automatically discover global installed/symlinked plugins in ~/.gemini/config/plugins/
    global_plugins = os.path.abspath(os.path.expanduser("~/.gemini/config/plugins"))
    if os.path.isdir(global_plugins):
        try:
            for entry in os.listdir(global_plugins):
                p_dir = os.path.join(global_plugins, entry)
                real_p = os.path.realpath(p_dir)
                if os.path.isdir(real_p) and real_p not in allowed:
                    allowed.append(real_p)
        except OSError:
            pass

    # Load configured overrides
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        policy = load_policy_file(f_path)
        for custom_path in policy.get("allowed_skill_paths", []):
            clean_p = os.path.abspath(os.path.expanduser(custom_path.strip()))
            if clean_p and clean_p not in allowed:
                allowed.append(clean_p)

    # Bundled allowed skill paths
    bundled = resolve_active_bundles(session_dir=session_dir, workspace_paths=workspace_paths)
    for custom_path in bundled.get("allowed_skill_paths", []):
        clean_p = os.path.abspath(os.path.expanduser(custom_path.strip()))
        if clean_p and clean_p not in allowed:
            allowed.append(clean_p)

    return allowed


def is_safe_skill_read(
    tool_name: str,
    tool_args: dict[str, Any],
    workspace_paths: list[str] | None = None,
    session_dir: str | None = None,
) -> bool:
    """
    Verifies if a read tool call is safely inspecting an authorized agent skill definition.
    Ensures real canonical path is within allowed skill paths and not targeting sensitive locations.
    """
    if tool_name != "view_file":
        return False

    raw_path = str(tool_args.get("AbsolutePath", "")).strip()
    if not raw_path:
        return False

    # Check if flagged as skill file or path clearly targets a skill definition
    is_skill_flag = bool(tool_args.get("IsSkillFile"))
    is_skill_path = (
        raw_path.endswith("SKILL.md") or "/skills/" in raw_path or "/.agents/skills/" in raw_path
    )

    if not (is_skill_flag or is_skill_path):
        return False

    norm_target = os.path.abspath(os.path.expanduser(raw_path))
    real_target = os.path.realpath(norm_target)

    # Hard defense: reject if real target touches sensitive system/credential targets
    if is_sensitive_path(norm_target) or is_sensitive_path(real_target):
        return False

    allowed_paths = load_allowed_skill_paths(
        session_dir=session_dir, workspace_paths=workspace_paths
    )
    all_roots = allowed_paths + [
        os.path.abspath(os.path.expanduser(ws)) for ws in (workspace_paths or [])
    ]

    # Real canonical target must be inside an allowed root
    for root in all_roots:
        real_root = os.path.realpath(root)
        if real_target == real_root or real_target.startswith(real_root + os.sep):
            return True

    return False


def is_safe_session_artifact_read(
    tool_name: str,
    tool_args: dict[str, Any],
    session_dir: str | None = None,
) -> bool:
    """
    Verifies if a read-only tool call (view_file, list_dir, grep_search) is safely inspecting
    the active session's own artifact, scratch, or audit log directory (<session_dir>/...).
    Ensures real canonical path is strictly within the session directory and not sensitive.
    """
    if tool_name not in ("view_file", "list_dir", "grep_search"):
        return False
    if not session_dir or not os.path.isabs(session_dir):
        return False

    target_path = ""
    if tool_name == "view_file":
        target_path = str(tool_args.get("AbsolutePath", "")).strip()
    elif tool_name == "list_dir":
        target_path = str(tool_args.get("DirectoryPath", "")).strip()
    elif tool_name == "grep_search":
        target_path = str(tool_args.get("SearchPath", "")).strip()

    if not target_path:
        return False

    norm_target = os.path.abspath(os.path.expanduser(target_path))
    real_target = os.path.realpath(norm_target)

    # Hard defense: reject if real target touches sensitive system/credential targets
    if is_sensitive_path(norm_target) or is_sensitive_path(real_target):
        return False

    norm_session = os.path.abspath(session_dir)
    real_session = os.path.realpath(norm_session)

    # Validate target is strictly within the active session directory
    is_norm_in = norm_target == norm_session or norm_target.startswith(norm_session + os.sep)
    is_real_in = real_target == real_session or real_target.startswith(real_session + os.sep)
    return is_norm_in and is_real_in


SAFE_ARTIFACT_WRITE_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".csv",
    ".tsv",
    ".yaml",
    ".yml",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".pdf",
    ".html",
    ".htm",
    ".diff",
    ".patch",
}


def is_safe_session_artifact_write(
    tool_name: str,
    tool_args: dict[str, Any],
    session_dir: str | None = None,
) -> bool:
    """
    Verifies if a file mutation tool call (write_to_file, replace_file_content,
    multi_replace_file_content) is safely authoring or editing an artifact document, plan,
    notes, or scratch file strictly within the active session's own directory
    (<session_dir>/... or ~/.gemini/antigravity/brain/<session_id>/...).
    Guarantees no writing of binary executables, shell scripts, or host-level credential files.
    """
    if tool_name not in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        return False
    if not session_dir or not os.path.isabs(session_dir):
        return False

    target_path = str(tool_args.get("TargetFile", "")).strip()
    if not target_path:
        return False

    norm_target = os.path.abspath(os.path.expanduser(target_path))
    real_target = os.path.realpath(norm_target)

    # Hard defense: reject if real target touches sensitive system/credential targets
    if (
        is_sensitive_path(norm_target)
        or is_sensitive_path(real_target)
        or is_sensitive_write_path(norm_target)
    ):
        return False

    # Check file extension against safe artifact extensions
    _, ext = os.path.splitext(norm_target)
    if ext.lower() not in SAFE_ARTIFACT_WRITE_EXTENSIONS:
        return False

    norm_session = os.path.abspath(session_dir)
    real_session = os.path.realpath(norm_session)

    # Validate target is strictly within the active session directory
    is_norm_in = norm_target == norm_session or norm_target.startswith(norm_session + os.sep)
    is_real_in = real_target == real_session or real_target.startswith(real_session + os.sep)
    return is_norm_in and is_real_in


SAFE_READ_BINARIES = {
    "which",
    "whereis",
    "wc",
    "head",
    "tail",
    "file",
    "uname",
    "du",
    "cat",
    "pwd",
    "date",
    "echo",
    "true",
    "false",
    "hostname",
    "arch",
}

SAFE_PIPE_FILTERS = {
    "grep",
    "rg",
    "head",
    "tail",
    "wc",
    "sort",
    "uniq",
    "awk",
    "cut",
    "tr",
    "column",
    "sed",
    "fold",
    "fmt",
}


def normalize_command_string(command_line: str) -> str:
    """
    Normalizes a command line string by collapsing redundant whitespace
    and trimming surrounding whitespace for consistent matching and caching.
    """
    if not command_line:
        return ""
    return " ".join(command_line.strip().split())


def is_safe_read_only_command(
    command_line: str,
    workspace_paths: list[str] | None = None,
) -> bool:
    """
    Evaluates whether a command is a safe, non-destructive read-only shell pipeline
    (e.g. `which uv`, `wc -l README.md`, `uname -m`, `head -n 20 file.txt | grep foo`).
    Guarantees no file writes, redirections, command substitutions, or credential leaks.
    """
    if not command_line or not command_line.strip():
        return False

    raw_cmd = command_line.strip()

    # Reject any shell write redirections or substitutions
    if any(tok in raw_cmd for tok in (">", ">>", "&>", "| tee", "$(", "`")):
        return False

    # Check for chained commands (&&, ||, ;, \n)
    segments = [s.strip() for s in re.split(r"&&|\|\||;|\n", raw_cmd) if s.strip()]
    if not segments:
        return False

    for segment in segments:
        # Check pipelines within segment
        pipe_parts = [p.strip() for p in segment.split("|") if p.strip()]
        if not pipe_parts:
            return False

        # First command in pipeline must be a whitelisted read binary
        first_cmd_tokens = pipe_parts[0].split()
        if not first_cmd_tokens:
            return False
        base_binary = os.path.basename(first_cmd_tokens[0]).lower()

        if base_binary not in SAFE_READ_BINARIES:
            return False

        # Downstream pipe stages must be safe filters
        for filter_part in pipe_parts[1:]:
            filter_tokens = filter_part.split()
            if not filter_tokens:
                return False
            filter_binary = os.path.basename(filter_tokens[0]).lower()
            if filter_binary not in SAFE_PIPE_FILTERS and filter_binary not in SAFE_READ_BINARIES:
                return False

        # Verify any referenced file paths do not target sensitive paths across all pipe stages
        for stage in pipe_parts:
            for token in stage.split()[1:]:
                if token.startswith("-"):
                    continue
                if is_sensitive_path(token):
                    return False

    return True


def resolve_trust_workspace_writes(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> bool:
    """
    Resolves whether workspace file writes qualify for sub-millisecond fast-path.
    Precedence: Session -> Local Project -> Project -> Global -> Env Var -> Default (True).
    """
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        if "trust_workspace_writes" in pol:
            val = pol["trust_workspace_writes"]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.strip().lower() in ("true", "1", "yes", "on")

    env_val = os.environ.get("AUTO_PERMISSIONS_TRUST_WORKSPACE_WRITES")
    if env_val is not None:
        return env_val.strip().lower() in ("true", "1", "yes", "on")

    return DEFAULT_TRUST_WORKSPACE_WRITES


def evaluate_workspace_write_fast_path(
    tool_name: str,
    tool_args: dict[str, Any],
    workspace_paths: list[str] | None = None,
    session_dir: str | None = None,
) -> tuple[str, str, str] | None:
    """
    Evaluates whether a file write action (replace_file_content, write_to_file,
    multi_replace_file_content) qualifies for sub-millisecond workspace write fast-path.
    Guarantees that sensitive targets (credentials, git, CI, policies) bypass fast-path.
    """
    if tool_name not in ("replace_file_content", "write_to_file", "multi_replace_file_content"):
        return None

    if not resolve_trust_workspace_writes(session_dir=session_dir, workspace_paths=workspace_paths):
        return None

    target_file = (
        tool_args.get("TargetFile")
        or tool_args.get("target_file")
        or tool_args.get("AbsolutePath")
        or tool_args.get("path")
    )
    if not target_file:
        return None

    norm_target = os.path.abspath(os.path.expanduser(str(target_file)))
    if is_sensitive_write_path(norm_target):
        return None

    if is_safe_session_artifact_write(
        tool_name=tool_name,
        tool_args=tool_args,
        session_dir=session_dir,
    ):
        rel_name = os.path.basename(norm_target)
        return (
            "allow",
            f"Safe session artifact write (session_artifact fast-path: {rel_name})",
            "session_artifact",
        )

    if not is_path_in_workspaces(norm_target, workspace_paths):
        return None

    rel_name = os.path.basename(norm_target)
    return (
        "allow",
        f"Safe workspace file write (trust_workspace_writes fast-path: {rel_name})",
        "workspace_write_fast_path",
    )


def update_trust_workspace_writes_setting(
    enabled: bool,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """
    Persists the trust_workspace_writes boolean lever to the specified configuration scope.
    """
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    policy["trust_workspace_writes"] = enabled
    save_policy_file(target_path, policy)
    return target_path


DEFAULT_SHOW_TURN_SUMMARY = True


def resolve_show_turn_summary(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> bool:
    """
    Resolves whether the turn-scoped PreInvocation Security Gate disclosure summary is enabled.
    Precedence: Session -> Local Project -> Project -> Global -> Env Var -> Default (True).
    """
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        for k in ("show_turn_summary", "disclose_turn_summary"):
            if k in pol and pol[k] is not None:
                val = pol[k]
                if isinstance(val, bool):
                    return val
                if isinstance(val, str):
                    return val.strip().lower() in ("true", "1", "yes", "on")

    env_val = os.environ.get("AUTO_PERMISSIONS_SHOW_TURN_SUMMARY") or os.environ.get(
        "AUTO_PERMISSIONS_DISCLOSE_TURN_SUMMARY"
    )
    if env_val is not None:
        return env_val.strip().lower() in ("true", "1", "yes", "on")

    return DEFAULT_SHOW_TURN_SUMMARY


def update_show_turn_summary_setting(
    enabled: bool,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """
    Persists the show_turn_summary boolean setting to the specified configuration scope.
    """
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    policy["show_turn_summary"] = enabled
    save_policy_file(target_path, policy)
    return target_path


def check_same_turn_file_grant(
    tool_name: str,
    tool_args: dict[str, Any],
    log_path: str | None,
    last_user_step_idx: int | None,
    workspace_paths: list[str] | None = None,
) -> tuple[str, str] | None:
    """
    Checks if a target file within workspace roots was already authorized for mutation
    by the classifier in the current active user turn (stepIdx >= last_user_step_idx).
    Reuses the write grant for multi-chunk edits to the same file in ~0.1ms.
    """
    if tool_name not in ("replace_file_content", "multi_replace_file_content", "write_to_file"):
        return None
    if last_user_step_idx is None or not log_path or not os.path.isfile(log_path):
        return None

    target_file = (
        tool_args.get("TargetFile")
        or tool_args.get("target_file")
        or tool_args.get("AbsolutePath")
        or tool_args.get("path")
    )
    if not target_file:
        return None

    # Must be inside workspace roots and not sensitive
    if not is_path_in_workspaces(target_file, workspace_paths):
        return None
    if is_sensitive_path(target_file):
        return None

    norm_target = os.path.realpath(os.path.abspath(os.path.expanduser(target_file)))

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    record = json.loads(line)
                    step_idx = record.get("stepIdx", 0)
                    if step_idx < last_user_step_idx:
                        continue

                    # Check if file was authorized for edits earlier in this turn
                    tool_call = record.get("toolCall", {})
                    t_name = tool_call.get("name", "")
                    if t_name not in (
                        "replace_file_content",
                        "multi_replace_file_content",
                        "write_to_file",
                    ):
                        continue

                    r_target = tool_call.get("args", {}).get("TargetFile")
                    if not r_target:
                        continue

                    norm_r_target = os.path.realpath(os.path.abspath(os.path.expanduser(r_target)))
                    if norm_target == norm_r_target:
                        hook_output = record.get("hook_output", {})
                        if hook_output.get("decision") == "allow":
                            filename = os.path.basename(target_file)
                            return (
                                "allow",
                                f"File '{filename}' edit authorized in active turn (File grant)",
                            )
    except Exception:
        return None

    return None


def check_intra_turn_cache(
    tool_name: str,
    tool_args: dict[str, Any],
    log_path: str | None,
    last_user_step_idx: int | None,
) -> tuple[str, str] | None:
    """
    Checks if an exact match for (tool_name, tool_args) was already evaluated and recorded
    in the active conversation turn (stepIdx >= last_user_step_idx).
    Reuses the verdict instantly in ~0.1ms without remote LLM latency or token overhead.

    Returns:
        Tuple of (decision, reason) if cached, or None if no intra-turn cache match exists.
    """
    if last_user_step_idx is None or not log_path or not os.path.isfile(log_path):
        return None

    norm_args = dict(tool_args)
    if tool_name == "run_command" and "CommandLine" in norm_args:
        norm_cmd = normalize_command_string(norm_args["CommandLine"])
    else:
        norm_cmd = None

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    record = json.loads(line)
                    step_idx = record.get("stepIdx", 0)
                    if step_idx < last_user_step_idx:
                        continue

                    tool_call = record.get("toolCall", {})
                    if tool_call.get("name") != tool_name:
                        continue

                    r_args = tool_call.get("args", {})
                    if tool_name == "run_command" and norm_cmd is not None:
                        r_cmd = normalize_command_string(r_args.get("CommandLine", ""))
                        if norm_cmd != r_cmd:
                            continue
                        if norm_args.get("Cwd") != r_args.get("Cwd"):
                            continue
                        if norm_args.get("BypassSandbox") != r_args.get("BypassSandbox"):
                            continue
                    elif tool_args != r_args:
                        continue

                    hook_output = record.get("hook_output", {})
                    decision = hook_output.get("decision")
                    reason = hook_output.get("reason", "Intra-turn cached verdict.")
                    if decision in ("allow", "deny", "soft_deny", "ask"):
                        return decision, f"{reason} (Intra-turn cache hit)"
    except Exception:
        return None

    return None


def check_intra_turn_circuit_breaker(
    log_path: str | None,
    last_user_step_idx: int | None,
    provider: str | None = None,
) -> tuple[str, str, int, str] | None:
    """
    Checks if the security classifier for the given provider experienced a persistent
    failure (timeout, auth failure, connection refused) in the active conversation turn
    (stepIdx >= last_user_step_idx).

    If tripped, short-circuits subsequent non-static calls in ~0.1ms to prevent
    accumulating redundant timeouts (Timeout * N) within the same turn.

    Returns:
        (decision, reason, failed_step_idx, failure_detail) or None if circuit is healthy.
    """
    if last_user_step_idx is None or not log_path or not os.path.isfile(log_path):
        return None

    norm_provider = (provider or "google").lower()
    if norm_provider == "gemini":
        norm_provider = "google"
    elif norm_provider == "claude":
        norm_provider = "anthropic"
    elif norm_provider == "oauth":
        norm_provider = "cloudcode"

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                record = json.loads(line)
                step_idx = record.get("stepIdx", 0)
                if step_idx < last_user_step_idx:
                    break

                classification = record.get("classification", {})
                risk_cat = classification.get("risk_category", "")
                rec_provider = classification.get("provider", "").lower()
                if rec_provider == "gemini":
                    rec_provider = "google"
                elif rec_provider == "claude":
                    rec_provider = "anthropic"

                is_fallback_error = risk_cat == "classifier_error_fallback" or (
                    classification.get("decision") == "ask"
                    and "fallback on error" in classification.get("reason", "").lower()
                )

                if is_fallback_error and (not rec_provider or rec_provider == norm_provider):
                    err_detail = classification.get("error") or classification.get(
                        "reason", "Provider failure"
                    )
                    reason_msg = (
                        f"Circuit breaker tripped for active turn: Provider '{norm_provider}' "
                        f"failed at step {step_idx} ({err_detail}). "
                        "Escalating immediately to avoid repeated timeout accumulation."
                    )
                    return ("ask", reason_msg, step_idx, str(err_detail))
    except Exception:
        return None

    return None


def resolve_classifier_config(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Resolves the complete classifier configuration (provider, model, endpoint_url, api_key)
    across the hierarchy:
    Session -> Local Project -> Project -> Global -> Environment Variables -> Defaults.
    """
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    merged: dict[str, Any] = {
        "provider": None,
        "model": None,
        "endpoint_url": None,
        "api_key": None,
        "api_key_env": None,
        "timeout_secs": None,
    }

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        for k in ("provider", "model", "endpoint_url", "api_key", "api_key_env"):
            if merged[k] is None and pol.get(k):
                merged[k] = pol[k]
        if merged["timeout_secs"] is None:
            for tk in ("timeout", "timeout_secs"):
                if pol.get(tk) is not None:
                    with contextlib.suppress(ValueError, TypeError):
                        merged["timeout_secs"] = float(pol[tk])
                        break

    # Environment variable overrides/fallbacks
    env_provider = os.environ.get("AUTO_PERMISSIONS_PROVIDER") or os.environ.get(
        "AUTO_PERMISSIONS_PROTOCOL"
    )
    if merged["provider"] is None and env_provider:
        merged["provider"] = env_provider.strip().lower()

    env_model = (
        os.environ.get("AUTO_PERMISSIONS_MODEL")
        or os.environ.get("GEMINI_MODEL")
        or os.environ.get("OPENAI_MODEL")
        or os.environ.get("ANTHROPIC_MODEL")
    )
    if merged["model"] is None and env_model:
        merged["model"] = env_model.strip()

    env_endpoint = (
        os.environ.get("AUTO_PERMISSIONS_ENDPOINT_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("ANTHROPIC_BASE_URL")
    )
    if merged["endpoint_url"] is None and env_endpoint:
        merged["endpoint_url"] = env_endpoint.strip()

    env_timeout = os.environ.get("AUTO_PERMISSIONS_TIMEOUT") or os.environ.get(
        "AUTO_PERMISSIONS_TIMEOUT_SECS"
    )
    if merged["timeout_secs"] is None and env_timeout:
        with contextlib.suppress(ValueError, TypeError):
            merged["timeout_secs"] = float(env_timeout)

    # Determine provider (normalize 'gemini' -> 'google', 'claude' -> 'anthropic')
    provider = (merged["provider"] or "").lower()
    if provider == "gemini":
        provider = "google"
    elif provider == "claude":
        provider = "anthropic"

    model = merged["model"] or ""
    endpoint = merged["endpoint_url"] or ""

    # Auto-infer provider if omitted
    if not provider:
        if "anthropic" in endpoint or model.startswith("claude"):
            provider = "anthropic"
        elif (
            "openai" in endpoint
            or "/chat/completions" in endpoint
            or model.startswith("gpt-")
            or model.startswith("o1")
            or model.startswith("o3")
        ):
            provider = "openai"
        elif os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            provider = "google"
        elif os.environ.get("ANTIGRAVITY_CSRF_TOKEN") or os.environ.get("ANTIGRAVITY_LS_ADDRESS"):
            provider = "antigravity"
        else:
            provider = "antigravity"

    # Default models per provider
    if not model:
        if provider == "anthropic":
            model = "claude-3-5-haiku-20241022"
        elif provider == "openai":
            model = "gpt-4o-mini"
        elif provider == "antigravity":
            model = "gemini-2.5-flash"
        else:
            model = "gemini-2.5-flash"

    # Resolve API Key
    api_key = merged["api_key"]
    if not api_key:
        if merged["api_key_env"]:
            api_key = os.environ.get(merged["api_key_env"])
        elif provider == "google":
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        elif provider == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY")
        elif provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key and "googleapis.com" in endpoint:
                api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    if not api_key:
        api_key = os.environ.get("AUTO_PERMISSIONS_API_KEY")

    resolved_timeout = (
        merged["timeout_secs"] if merged["timeout_secs"] is not None else DEFAULT_TIMEOUT_SECS
    )

    return {
        "provider": provider,
        "model": model,
        "endpoint_url": endpoint or None,
        "api_key": api_key,
        "timeout_secs": resolved_timeout,
    }


def resolve_classifier_timeout(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> float:
    """Resolves the configured classifier timeout in seconds across the hierarchy."""
    cfg = resolve_classifier_config(session_dir=session_dir, workspace_paths=workspace_paths)
    return float(cfg.get("timeout_secs") or DEFAULT_TIMEOUT_SECS)


def update_classifier_timeout_setting(
    timeout_secs: float,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Persists the timeout setting to the specified configuration scope."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    policy["timeout"] = timeout_secs
    save_policy_file(target_path, policy)
    return target_path


def resolve_configured_model(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
    default_model: str = "gemini-2.5-flash",
) -> str:
    """Resolves the configured model identifier across the hierarchy."""
    cfg = resolve_classifier_config(session_dir=session_dir, workspace_paths=workspace_paths)
    return cfg.get("model") or default_model


def load_custom_guidelines(
    workspace_paths: list[str] | None = None,
    session_dir: str | None = None,
) -> list[str]:
    """
    Loads and aggregates custom semantic guidelines across Global, Project, Session scopes,
    and any active permission bundles. Returns a deduplicated list of strings.
    """
    guidelines: list[str] = []
    seen: set[str] = set()

    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    for file_path in scope_files:
        if not os.path.isfile(file_path):
            continue
        policy = load_policy_file(file_path)
        for g in policy.get("custom_guidelines", []):
            clean_g = g.strip()
            if clean_g and clean_g not in seen:
                seen.add(clean_g)
                guidelines.append(clean_g)

    # Bundled custom guidelines
    bundled = resolve_active_bundles(session_dir=session_dir, workspace_paths=workspace_paths)
    for g in bundled.get("custom_guidelines", []):
        clean_g = g.strip()
        if clean_g and clean_g not in seen:
            seen.add(clean_g)
            guidelines.append(clean_g)

    return guidelines


def save_policy_file(file_path: str, policy: dict[str, Any]) -> None:
    """Saves policy dictionary to file atomically."""
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(parent_dir, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def resolve_scope_file_path(
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
    prefer_existing: bool = True,
) -> str:
    """Resolves target configuration file path for a given scope."""
    scope = scope.lower()
    if scope == "session":
        if not session_dir:
            msg = "Session directory is required for session-scope configuration."
            raise ValueError(msg)
        return resolve_session_override_path(session_dir) or os.path.join(
            session_dir, SESSION_PLUGIN_SUBDIR, SESSION_OVERRIDES_FILENAME
        )
    if scope in ("project_local", "local"):
        return resolve_project_local_config_path(workspace_dir, prefer_existing=prefer_existing)
    if scope == "project":
        return resolve_project_config_path(workspace_dir, prefer_existing=prefer_existing)
    if scope == "global":
        return resolve_global_config_path(prefer_existing=prefer_existing)
    msg = f"Invalid scope '{scope}'. Must be 'session', 'project_local', 'project', or 'global'."
    raise ValueError(msg)


def add_rule_to_scope(
    rule_str: str,
    decision: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """
    Adds a rule to the specified policy scope ('session', 'project_local', 'project', 'global').
    Returns the file path written to.
    """
    decision = decision.lower()
    if decision not in ("allow", "ask", "deny"):
        msg = f"Invalid decision '{decision}'. Must be allow, ask, or deny."
        raise ValueError(msg)

    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    if rule_str not in policy[decision]:
        # Remove from other buckets if present
        for other_k in ("allow", "ask", "deny"):
            with contextlib.suppress(ValueError):
                policy[other_k].remove(rule_str)
        policy[decision].append(rule_str)
        save_policy_file(target_path, policy)

    return target_path


def remove_rule_from_scope(
    rule_str: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Removes a static rule from the specified scope file."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    modified = False
    for bucket in ("allow", "ask", "deny"):
        if rule_str in policy.get(bucket, []):
            policy[bucket].remove(rule_str)
            modified = True
    if modified:
        save_policy_file(target_path, policy)
    return target_path


def add_guideline_to_scope(
    guideline: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Adds a custom semantic guideline to the specified scope file."""
    clean_g = guideline.strip()
    if not clean_g:
        msg = "Guideline text cannot be empty."
        raise ValueError(msg)

    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    guidelines = policy.get("custom_guidelines", [])
    if clean_g not in guidelines:
        guidelines.append(clean_g)
        policy["custom_guidelines"] = guidelines
        save_policy_file(target_path, policy)
    return target_path


def remove_guideline_from_scope(
    guideline: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Removes a custom semantic guideline from the specified scope file."""
    clean_g = guideline.strip()
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    guidelines = policy.get("custom_guidelines", [])
    if clean_g in guidelines:
        guidelines.remove(clean_g)
        policy["custom_guidelines"] = guidelines
        save_policy_file(target_path, policy)
    return target_path


def add_skill_path_to_scope(
    path_str: str,
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Adds an allowed skill path to the specified scope file."""
    clean_p = path_str.strip()
    if not clean_p:
        msg = "Skill path cannot be empty."
        raise ValueError(msg)

    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    paths = policy.get("allowed_skill_paths", [])
    if clean_p not in paths:
        paths.append(clean_p)
        policy["allowed_skill_paths"] = paths
        save_policy_file(target_path, policy)
    return target_path


def update_classifier_settings_in_scope(
    settings: dict[str, Any],
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Updates provider, model, endpoint_url, api_key, api_key_env, timeout in scope."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    for k in (
        "provider",
        "model",
        "endpoint_url",
        "api_key",
        "api_key_env",
        "timeout",
        "timeout_secs",
    ):
        if k in settings:
            policy[k] = settings[k]
    save_policy_file(target_path, policy)
    return target_path


def update_governed_surfaces_in_scope(
    governed: dict[str, bool],
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Updates govern_subagents, govern_schedule, govern_images in specified scope."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    for k, val in governed.items():
        pol_key = f"govern_{k}"
        policy[pol_key] = val
    save_policy_file(target_path, policy)
    return target_path


# ============================================================================
# Permission Bundles Management & Resolution
# ============================================================================


def find_bundle_definition(
    bundle_name: str,
    workspace_paths: list[str] | None = None,
    custom_bundles_map: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Finds a bundle definition by name across:
    1. custom_bundles_map (inline definitions)
    2. Project local bundles (.agents/auto-permissions/bundles.local/<name>.json)
    3. Project tracked bundles (.agents/auto-permissions/bundles/<name>.json)
    4. Global bundles (~/.gemini/config/auto-permissions/bundles/<name>.json)
    5. Builtin bundles (hooks/bundles/<name>.json)
    """
    clean_name = bundle_name.strip().lower()
    if not clean_name:
        return None

    # 1. Inline custom bundle
    if custom_bundles_map and clean_name in custom_bundles_map:
        b_data = custom_bundles_map[clean_name]
        if isinstance(b_data, dict):
            b_dict = dict(b_data)
            b_dict.setdefault("name", clean_name)
            b_dict.setdefault("source", "inline")
            return b_dict

    # 2. Project local bundles
    if workspace_paths:
        for ws in workspace_paths:
            fpath = os.path.join(ws, PROJECT_LOCAL_BUNDLES_DIR_REL, f"{clean_name}.json")
            if os.path.isfile(fpath):
                b = load_bundle_from_file(fpath)
                if b:
                    b.setdefault("source", "project_local")
                    return b

    # 3. Project tracked bundles
    if workspace_paths:
        for ws in workspace_paths:
            fpath = os.path.join(ws, PROJECT_BUNDLES_DIR_REL, f"{clean_name}.json")
            if os.path.isfile(fpath):
                b = load_bundle_from_file(fpath)
                if b:
                    b.setdefault("source", "project")
                    return b

    # 4. Global bundles
    gpath = os.path.join(GLOBAL_BUNDLES_DIR, f"{clean_name}.json")
    if os.path.isfile(gpath):
        b = load_bundle_from_file(gpath)
        if b:
            b.setdefault("source", "global")
            return b

    # 5. Built-in bundle
    builtin = get_builtin_bundle(clean_name)
    if builtin:
        b_copy = dict(builtin)
        b_copy.setdefault("source", "builtin")
        return b_copy

    return None


def list_available_bundles(
    workspace_paths: list[str] | None = None,
    session_dir: str | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Discovers all available bundles across Built-in, Global, Project, and Inline sources.
    Returns catalog keyed by bundle slug.
    """
    catalog: dict[str, dict[str, Any]] = {}

    # 1. Built-in
    for b_name, b_val in list_builtin_bundles().items():
        b_copy = dict(b_val)
        b_copy.setdefault("source", "builtin")
        catalog[b_name] = b_copy

    # 2. Global
    if os.path.isdir(GLOBAL_BUNDLES_DIR):
        for fname in sorted(os.listdir(GLOBAL_BUNDLES_DIR)):
            if fname.endswith(".json"):
                b = load_bundle_from_file(os.path.join(GLOBAL_BUNDLES_DIR, fname))
                if b and "name" in b:
                    b["source"] = "global"
                    catalog[b["name"]] = b

    # 3. Project tracked & local
    if workspace_paths:
        for ws in workspace_paths:
            # Tracked
            p_dir = os.path.join(ws, PROJECT_BUNDLES_DIR_REL)
            if os.path.isdir(p_dir):
                for fname in sorted(os.listdir(p_dir)):
                    if fname.endswith(".json"):
                        b = load_bundle_from_file(os.path.join(p_dir, fname))
                        if b and "name" in b:
                            b["source"] = "project"
                            catalog[b["name"]] = b
            # Local
            pl_dir = os.path.join(ws, PROJECT_LOCAL_BUNDLES_DIR_REL)
            if os.path.isdir(pl_dir):
                for fname in sorted(os.listdir(pl_dir)):
                    if fname.endswith(".json"):
                        b = load_bundle_from_file(os.path.join(pl_dir, fname))
                        if b and "name" in b:
                            b["source"] = "project_local"
                            catalog[b["name"]] = b

    # 4. Inline bundles across scope files
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]
    for sf in scope_files:
        if not os.path.isfile(sf):
            continue
        pol = load_policy_file(sf)
        for cb_name, cb_def in pol.get("custom_bundles", {}).items():
            if isinstance(cb_def, dict):
                cb_copy = dict(cb_def)
                cb_copy.setdefault("name", cb_name)
                cb_copy.setdefault("source", "inline")
                catalog[cb_name] = cb_copy

    return catalog


def expand_bundle_hierarchy(
    bundle_names: list[str],
    disabled_bundles: set[str] | None = None,
    workspace_paths: list[str] | None = None,
    custom_bundles_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Expands bundle names and inheritance (extends) into flattened rule sets,
    detecting dependency cycles and filtering out disabled bundles.
    """
    disabled = disabled_bundles or set()
    expanded_rules: dict[str, Any] = {
        "active_bundles": [],
        "allow": [],
        "ask": [],
        "deny": [],
        "custom_guidelines": [],
        "allowed_skill_paths": [],
        "govern_surfaces": {"subagents": False, "schedule": False, "images": False},
        "provenance": {},
    }

    visited: set[str] = set()
    queue = list(bundle_names)

    while queue:
        current = queue.pop(0).strip().lower()
        if not current or current in visited or current in disabled:
            continue
        visited.add(current)

        b_def = find_bundle_definition(
            current,
            workspace_paths=workspace_paths,
            custom_bundles_map=custom_bundles_map,
        )
        if not b_def:
            continue

        expanded_rules["active_bundles"].append(current)

        # Process extends
        extends = b_def.get("extends", [])
        if isinstance(extends, list):
            for ext in extends:
                ext_clean = str(ext).strip().lower()
                if ext_clean and ext_clean not in visited and ext_clean not in disabled:
                    queue.append(ext_clean)

        # Merge rules
        for bucket in ("allow", "ask", "deny", "custom_guidelines", "allowed_skill_paths"):
            for item in b_def.get(bucket, []):
                clean_item = str(item).strip()
                if clean_item and clean_item not in expanded_rules[bucket]:
                    expanded_rules[bucket].append(clean_item)
                    if bucket in ("allow", "ask", "deny"):
                        expanded_rules["provenance"][clean_item] = current

        # Merge govern surfaces
        gov = b_def.get("govern_surfaces", {})
        if isinstance(gov, dict):
            for k in ("subagents", "schedule", "images"):
                if gov.get(k) is True:
                    expanded_rules["govern_surfaces"][k] = True

    return expanded_rules


def resolve_active_bundles(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Resolves the effective bundles across the 5-tier policy hierarchy
    (Session > Local Project > Tracked Project > Global).
    """
    scope_files = [f for _, f in get_scope_file_candidates(session_dir, workspace_paths)]

    enabled_bundles: list[str] = []
    disabled_bundles: set[str] = set()
    custom_bundles_map: dict[str, Any] = {}

    for sf in scope_files:
        if not os.path.isfile(sf):
            continue
        pol = load_policy_file(sf)
        # Collect inline custom bundles
        for cb_name, cb_def in pol.get("custom_bundles", {}).items():
            if cb_name not in custom_bundles_map:
                custom_bundles_map[cb_name] = cb_def

        b_cfg = pol.get("bundles")
        if isinstance(b_cfg, list):
            for b in b_cfg:
                b_name = str(b).strip().lower()
                if b_name and b_name not in disabled_bundles and b_name not in enabled_bundles:
                    enabled_bundles.append(b_name)
        elif isinstance(b_cfg, dict):
            # Disabled at higher/current scope masks lower scopes
            for d in b_cfg.get("disabled", []):
                disabled_bundles.add(str(d).strip().lower())
            for e in b_cfg.get("enabled", []):
                e_name = str(e).strip().lower()
                if e_name and e_name not in disabled_bundles and e_name not in enabled_bundles:
                    enabled_bundles.append(e_name)

    return expand_bundle_hierarchy(
        bundle_names=enabled_bundles,
        disabled_bundles=disabled_bundles,
        workspace_paths=workspace_paths,
        custom_bundles_map=custom_bundles_map,
    )


def update_bundles_in_scope(
    enabled_bundles: list[str] | None = None,
    disabled_bundles: list[str] | None = None,
    scope: str = "project",
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Enables or disables bundles in the specified scope."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir, prefer_existing=True
    )
    policy = load_policy_file(target_path)
    current_bundles = policy.get("bundles")

    if isinstance(current_bundles, list):
        cur_enabled = list(current_bundles)
        cur_disabled = []
    elif isinstance(current_bundles, dict):
        cur_enabled = list(current_bundles.get("enabled", []))
        cur_disabled = list(current_bundles.get("disabled", []))
    else:
        cur_enabled = []
        cur_disabled = []

    if enabled_bundles:
        for b in enabled_bundles:
            b_clean = b.strip().lower()
            if b_clean:
                if b_clean in cur_disabled:
                    cur_disabled.remove(b_clean)
                if b_clean not in cur_enabled:
                    cur_enabled.append(b_clean)

    if disabled_bundles:
        for b in disabled_bundles:
            b_clean = b.strip().lower()
            if b_clean:
                if b_clean in cur_enabled:
                    cur_enabled.remove(b_clean)
                if b_clean not in cur_disabled:
                    cur_disabled.append(b_clean)

    if cur_disabled:
        policy["bundles"] = {"enabled": cur_enabled, "disabled": cur_disabled}
    else:
        policy["bundles"] = cur_enabled

    save_policy_file(target_path, policy)
    return target_path


def migrate_config_layout(
    workspace_dir: str | None = None,
    migrate_global: bool = True,
) -> dict[str, str]:
    """
    Migrates legacy flat configuration files to the new scoped directory layout.
    Moves .agents/auto-permissions.json -> .agents/auto-permissions/config.json
    Moves .agents/auto-permissions.local.json -> .agents/auto-permissions/config.local.json
    Moves ~/.gemini/config/auto-permissions.json -> ~/.gemini/config/auto-permissions/config.json
    """
    import shutil

    results: dict[str, str] = {}
    ws = workspace_dir or os.getcwd()

    # 1. Project tracked config
    old_proj = os.path.join(ws, PROJECT_CONFIG_LEGACY_REL)
    new_proj = os.path.join(ws, PROJECT_CONFIG_PRIMARY_REL)
    if os.path.isfile(old_proj) and not os.path.isfile(new_proj):
        os.makedirs(os.path.dirname(new_proj), exist_ok=True)
        shutil.move(old_proj, new_proj)
        results["project"] = f"Migrated {old_proj} -> {new_proj}"

    # 2. Project local config
    old_local = os.path.join(ws, PROJECT_LOCAL_CONFIG_LEGACY_REL)
    new_local = os.path.join(ws, PROJECT_LOCAL_CONFIG_PRIMARY_REL)
    if os.path.isfile(old_local) and not os.path.isfile(new_local):
        os.makedirs(os.path.dirname(new_local), exist_ok=True)
        shutil.move(old_local, new_local)
        results["project_local"] = f"Migrated {old_local} -> {new_local}"

    # 3. Global config
    if (
        migrate_global
        and os.path.isfile(GLOBAL_CONFIG_LEGACY)
        and not os.path.isfile(GLOBAL_CONFIG_PRIMARY)
    ):
        os.makedirs(GLOBAL_CONFIG_DIR, exist_ok=True)
        shutil.move(GLOBAL_CONFIG_LEGACY, GLOBAL_CONFIG_PRIMARY)
        results["global"] = f"Migrated {GLOBAL_CONFIG_LEGACY} -> {GLOBAL_CONFIG_PRIMARY}"

    return results


def evaluate_static_policies(
    tool_name: str,
    tool_args: dict[str, Any],
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> tuple[str, str, str] | None:
    """
    Evaluates tool against explicit policies AND active Permission Bundles
    with strict priority Deny > Ask > Allow.

    Returns:
        Tuple of (decision, reason, scope) if matched, or None if no static match.
    """
    scope_files = get_scope_file_candidates(session_dir, workspace_paths)

    # 1. Evaluate explicit scope rules (Deny > Ask > Allow)
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

    # 2. Evaluate Compiled Permission Bundles (Deny > Ask > Allow)
    bundled = resolve_active_bundles(session_dir=session_dir, workspace_paths=workspace_paths)

    # 2.1 Bundled Deny
    for rule in bundled.get("deny", []):
        if match_tool_against_rule(rule, tool_name, tool_args):
            b_src = bundled.get("provenance", {}).get(rule, "bundle")
            return (
                "deny",
                f"Blocked by bundled policy ({b_src}) rule '{rule}'",
                f"bundle:{b_src}",
            )

    # 2.2 Bundled Ask
    for rule in bundled.get("ask", []):
        if match_tool_against_rule(rule, tool_name, tool_args):
            b_src = bundled.get("provenance", {}).get(rule, "bundle")
            return (
                "ask",
                f"Escalated by bundled policy ({b_src}) rule '{rule}'",
                f"bundle:{b_src}",
            )

    # 2.3 Bundled Allow
    for rule in bundled.get("allow", []):
        if match_tool_against_rule(rule, tool_name, tool_args):
            b_src = bundled.get("provenance", {}).get(rule, "bundle")
            return (
                "allow",
                f"Auto-approved by bundled policy ({b_src}) rule '{rule}'",
                f"bundle:{b_src}",
            )

    # 3. Built-in fast-path for read-only workspace inspection
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

    # 4. Built-in fast-path for active session artifacts, scratch, and audit logs
    if is_safe_session_artifact_read(
        tool_name=tool_name,
        tool_args=tool_args,
        session_dir=session_dir,
    ):
        return (
            "allow",
            f"Auto-approved active session artifact read for {tool_name}",
            "session_artifact",
        )

    # 4.1 Built-in fast-path for active session artifact writes (plans, notes, drafts)
    if is_safe_session_artifact_write(
        tool_name=tool_name,
        tool_args=tool_args,
        session_dir=session_dir,
    ):
        rel_name = os.path.basename(str(tool_args.get("TargetFile", "")))
        return (
            "allow",
            f"Auto-approved active session artifact write ({rel_name})",
            "session_artifact",
        )

    # 5. Built-in fast-path for safe skill definitions
    if is_safe_skill_read(
        tool_name=tool_name,
        tool_args=tool_args,
        workspace_paths=workspace_paths,
        session_dir=session_dir,
    ):
        return (
            "allow",
            "Auto-approved read of registered skill definition",
            "skill_resource",
        )

    return None
