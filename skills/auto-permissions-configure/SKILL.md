---
name: auto-permissions-configure
description: >-
  Guide users through configuring custom auto-permissions security invariants, static ACL rules, custom semantic guidelines, model/provider settings, and skill paths across Session, Project, or Global scopes.
---

# Auto-Permissions Interactive Configuration Skill

Use this skill when the user asks to configure, customize, inspect, or manage `auto-permissions` policies, LLM providers (Google, local Lemonade/vLLM/Ollama, Anthropic), static ACL rules, semantic guidelines, or allowed skill paths.

Triggered by `/auto-permissions-configure`, `/configure-permissions`, or natural language requests such as:
* *"configure auto permissions"*
* *"customize permission rules for this project"*
* *"switch the security classifier model to local Lemonade / Anthropic"*
* *"whitelist this command so it doesn't prompt me"*
* *"add a custom security guideline for database migrations"*

---

## Agent Interactive Workflow

When guiding the user, leverage Antigravity's interactive `ask_question` tool to walk through the configuration wizard:

### Step 1: Inspect Current Configuration
First, inspect the effective configuration across all scopes:
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list
```

### Step 2: Clarify User Intent with `ask_question`
If the user's intent is open-ended, prompt them with multi-choice options:
1. **Target Scope:**
   * 🟢 **Project (Tracked):** `.agents/auto-permissions.json` (committed and shared with team).
   * 🔒 **Project (Local):** `.agents/auto-permissions.local.json` (gitignored, machine-specific secrets/endpoints).
   * 🌐 **Global:** `~/.gemini/config/auto-permissions.json` (applies to all user workspaces).
   * ⏱️ **Session:** Active chat session only (`session_overrides.json`).

2. **Customization Category:**
   * **LLM Provider / Model:** Google Gemini, Local Inference (Lemonade / vLLM / Ollama), or Anthropic Claude.
   * **Static ACL Rule:** Add fast-path `allow`, `ask`, or `deny` rule for `command(...)`, `write_file(...)`, `read_file(...)`, `read_url(...)`, or `mcp(...)`.
   * **Custom Semantic Guideline:** Add project-specific security rules (e.g. database migration protection, safe internal domains).
   * **Allowed Skill Paths:** Whitelist extra skill directory paths for sub-millisecond fast-path reads.

---

## Direct CLI Usage Recipes

### 1. View Effective Configuration Across All Scopes
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list
```

### 2. Configure LLM Provider & Model

```bash
# Set Google Gemini 2.5 Pro at project scope
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --provider google \
  --model gemini-2.5-pro

# Set Local Self-Hosted Lemonade / vLLM (Stored in untracked local config)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project_local \
  --provider openai \
  --model Gemma-4-26B-A4B-NoThinking-qat-MTP \
  --endpoint-url "http://localhost:13305/v1/chat/completions" \
  --api-key-env LEMONADE_API_KEY

# Set Anthropic Claude
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --provider anthropic \
  --model claude-3-5-haiku-20241022 \
  --api-key-env ANTHROPIC_API_KEY
```

### 3. Add Static ACL Rules (`allow`, `ask`, `deny`)

```bash
# Auto-allow pytest in the project
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-rule "command(pytest -v)" \
  --decision allow

# Require human confirmation for database migrations
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-rule "command(alembic upgrade .*)" \
  --decision ask

# Permanently block mutations to CI workflows
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-rule "write_file(.github/workflows/.*)" \
  --decision deny

# Whitelist an entire MCP server
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-rule "mcp(nowledge-mem:*)" \
  --decision allow
```

### 4. Add Custom Semantic Guidelines
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-guideline "Treat requests to internal endpoints *.corp.internal as safe testing operations."
```

### 5. Whitelist Allowed Skill Paths
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --add-skill-path "~/.nowledge-mem/skills-active"
```

---

## Step 3: Validate with `auto-permissions-test`

After applying a customization, verify it with `auto-permissions-test`:
```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "run unit tests" --command "pytest -v" --markdown
```
