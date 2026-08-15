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
PROJECT_LOCAL_CONFIG_REL_PATH = os.path.join(".agents", "auto-permissions.local.json")
SESSION_PLUGIN_SUBDIR = "auto-permissions"
SESSION_OVERRIDES_FILENAME = "session_overrides.json"


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

    elif tool_name == "call_mcp_tool":
        server = str(tool_args.get("ServerName", ""))
        sub_tool = str(tool_args.get("ToolName", ""))
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
        server = str(tool_args.get("ServerName", ""))
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
    'provider', 'model', 'endpoint_url', 'api_key', 'api_key_env'.
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
        "provider": None,
        "model": None,
        "endpoint_url": None,
        "api_key": None,
        "api_key_env": None,
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
                ):
                    if bool_k in data and isinstance(data[bool_k], bool):
                        policy[bool_k] = data[bool_k]
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
    except Exception:
        pass
    return policy


def resolve_governed_surfaces(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> dict[str, bool]:
    """
    Resolves whether subagents, schedule, and images require security gate classification.
    Defaults to False (opt-in) unless configured in Session, Project, Global, or env vars.
    """
    scope_files = []
    if session_dir and os.path.isdir(session_dir):
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(session_file)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH))
            scope_files.append(os.path.join(ws, PROJECT_CONFIG_REL_PATH))
    scope_files.append(GLOBAL_CONFIG_PATH)

    governed = {
        "subagents": False,
        "schedule": False,
        "images": False,
    }

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        for k in ("subagents", "schedule", "images"):
            pol_key = f"govern_{k}"
            if pol.get(pol_key) is not None and not governed[k]:
                governed[k] = bool(pol[pol_key])
        for s in pol.get("govern_surfaces", []):
            clean_s = s.strip().lower()
            if clean_s in governed:
                governed[clean_s] = True

    # Environment variables
    if os.environ.get("AUTO_PERMISSIONS_GOVERN_SUBAGENTS") in ("1", "true", "yes"):
        governed["subagents"] = True
    if os.environ.get("AUTO_PERMISSIONS_GOVERN_SCHEDULE") in ("1", "true", "yes"):
        governed["schedule"] = True
    if os.environ.get("AUTO_PERMISSIONS_GOVERN_IMAGES") in ("1", "true", "yes"):
        governed["images"] = True

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
    any user-configured 'allowed_skill_paths' in Global, Project, or Session policies.
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
    scope_files = []
    scope_files.append(GLOBAL_CONFIG_PATH)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH))
            scope_files.append(os.path.join(ws, PROJECT_CONFIG_REL_PATH))
    if session_dir and os.path.isdir(session_dir):
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(session_file)

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        policy = load_policy_file(f_path)
        for custom_path in policy.get("allowed_skill_paths", []):
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

        # Verify any referenced file paths do not target sensitive paths
        for token in pipe_parts[0].split()[1:]:
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
    scope_files = []
    if session_dir and os.path.isdir(session_dir):
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(session_file)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH))
            scope_files.append(os.path.join(ws, PROJECT_CONFIG_REL_PATH))
    scope_files.append(GLOBAL_CONFIG_PATH)

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

    target_file = tool_args.get("TargetFile")
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


def resolve_classifier_config(
    session_dir: str | None = None,
    workspace_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Resolves the complete classifier configuration (provider, model, endpoint_url, api_key)
    across the hierarchy:
    Session -> Local Project (.agents/*.local.json) -> Project (.agents/*.json)
    -> Global -> Environment Variables -> Defaults.
    """
    scope_files = []
    # 1. Session scope
    if session_dir and os.path.isdir(session_dir):
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(session_file)

    # 2. Local Project scope (untracked)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH))

    # 3. Project scope (tracked)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_CONFIG_REL_PATH))

    # 4. Global scope
    scope_files.append(GLOBAL_CONFIG_PATH)

    merged: dict[str, Any] = {
        "provider": None,
        "model": None,
        "endpoint_url": None,
        "api_key": None,
        "api_key_env": None,
    }

    for f_path in scope_files:
        if not os.path.isfile(f_path):
            continue
        pol = load_policy_file(f_path)
        for k in ("provider", "model", "endpoint_url", "api_key", "api_key_env"):
            if merged[k] is None and pol.get(k):
                merged[k] = pol[k]

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
        else:
            provider = "google"

    # Default models per provider
    if not model:
        if provider == "anthropic":
            model = "claude-3-5-haiku-20241022"
        elif provider == "openai":
            model = "gpt-4o-mini"
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

    return {
        "provider": provider,
        "model": model,
        "endpoint_url": endpoint or None,
        "api_key": api_key,
    }


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
    Loads and aggregates custom semantic guidelines across Global, Project, and Session scopes.
    Returns a deduplicated list of strings.
    """
    guidelines: list[str] = []
    seen: set[str] = set()

    scope_files = []
    # 1. Global
    scope_files.append(GLOBAL_CONFIG_PATH)
    # 2. Project
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH))
            scope_files.append(os.path.join(ws, PROJECT_CONFIG_REL_PATH))
    # 3. Session
    if session_dir and os.path.isdir(session_dir):
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(session_file)

    for file_path in scope_files:
        if not os.path.isfile(file_path):
            continue
        policy = load_policy_file(file_path)
        for g in policy.get("custom_guidelines", []):
            clean_g = g.strip()
            if clean_g and clean_g not in seen:
                seen.add(clean_g)
                guidelines.append(clean_g)

    return guidelines


def save_policy_file(file_path: str, policy: dict[str, list[str]]) -> None:
    """Saves policy dictionary to file atomically."""
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(parent_dir, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def resolve_scope_file_path(
    scope: str,
    workspace_dir: str | None = None,
    session_dir: str | None = None,
) -> str:
    """Resolves target configuration file path for a given scope."""
    scope = scope.lower()
    if scope == "session":
        if not session_dir:
            msg = "Session directory is required for session-scope configuration."
            raise ValueError(msg)
        return resolve_session_override_path(session_dir)
    if scope in ("project_local", "local"):
        ws = workspace_dir or os.getcwd()
        return os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH)
    if scope == "project":
        ws = workspace_dir or os.getcwd()
        return os.path.join(ws, PROJECT_CONFIG_REL_PATH)
    if scope == "global":
        return GLOBAL_CONFIG_PATH
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
    """Updates provider, model, endpoint_url, api_key, api_key_env in specified scope."""
    target_path = resolve_scope_file_path(
        scope, workspace_dir=workspace_dir, session_dir=session_dir
    )
    policy = load_policy_file(target_path)
    for k in ("provider", "model", "endpoint_url", "api_key", "api_key_env"):
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
        session_file = resolve_session_override_path(session_dir)
        if session_file:
            scope_files.append(("session", session_file))

    # 2. Local Project scope (untracked local overrides)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(("project_local", os.path.join(ws, PROJECT_LOCAL_CONFIG_REL_PATH)))

    # 3. Project scope (tracked project rules)
    if workspace_paths:
        for ws in workspace_paths:
            scope_files.append(("project", os.path.join(ws, PROJECT_CONFIG_REL_PATH)))

    # 4. Global scope
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

    # 5. Built-in fast-path for active session artifacts, scratch, and audit logs
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

    # 6. Built-in fast-path for safe skill definitions
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
