---
name: auto-permissions-fix
description: >-
  Generate and apply Antigravity permission ACL rules (allow, ask, deny) from audit log denials across Session, Project, or Global scopes.
---

# Auto-Permissions Fix Skill (Denial Remediation & ACL Generator)

Use this skill when the user asks to fix or allow a blocked tool call from the audit log, or configure explicit static rules to auto-approve, prompt, or hard-block specific commands and files.

## CLI Procedures

### 1. Auto-Fix Most Recent Denied Action
Allow the most recent denial in the active session:
```bash
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --last --allow --scope session
```

Allow the most recent denial for the entire repository project:
```bash
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --last --allow --scope project
```

### 2. Interactive Rule Generator
Run without flags to browse all recent denials, select candidate rule representations (`command(...)`, `write_file(...)`, `read_url(...)`, `mcp(server:tool)`), and choose the target scope:
```bash
python3 skills/auto-permissions-fix/scripts/fix_permissions.py
```

### 3. Explicit Rule Injection
Add a custom permission rule directly to a target scope:
```bash
# Allow a command at project level:
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "command(uv lock)" --decision allow --scope project

# Allow all MCP tools on a specific server for the active session:
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "mcp(nowledge-mem:*)" --decision allow --scope session
```

## Policy Scopes

| Scope | Location | Target Lifecycle |
| :--- | :--- | :--- |
| **`session`** | `<session_dir>/session_overrides.json` | Active conversation only (disposed with session). |
| **`project`** | `<workspace>/.agents/auto-permissions.json` | Persistent for the workspace/git repo. |
| **`global`** | `~/.gemini/config/auto-permissions.json` | Applies across all projects on the system. |
