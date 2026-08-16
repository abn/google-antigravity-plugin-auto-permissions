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

When guiding the user, leverage Antigravity's interactive `ask_question` tool using **strictly sequential, conditional branching** (never bundle provider selection and provider-specific model cards into the same turn):

### Step 1: Inspect Current Configuration
First, inspect the effective configuration across all scopes:
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list
```

### Step 2: Scope & Category Selection (`ask_question` Turn 1)
Prompt the user to choose the target scope and customization category:
1. **Target Scope:**
   * 🟢 **Project (Tracked):** `.agents/auto-permissions/config.json` (committed and shared with team).
   * 🔒 **Project (Local):** `.agents/auto-permissions/config.local.json` (gitignored, machine-specific secrets/endpoints).
   * 🌐 **Global:** `~/.gemini/config/auto-permissions/config.json` (applies to all user workspaces).
   * ⏱️ **Session:** Active chat session only (`<session_dir>/auto-permissions/session_overrides.json`).

2. **Customization Category:**
   * **Permission Bundles:** Enable or disable curated tool whitelists (`git-inspect`, `gh-readonly`, `python-tooling`, `rust-tooling`, `node-tooling`, `container-inspect`, `dev-docs-read`, `mcp-nmem`).
   * **LLM Provider & Model:** Configure Google Gemini, Local GPU Inference (Lemonade / vLLM / Ollama), or Anthropic Claude.
   * **Workspace Writes Trust:** Toggle 0.1ms fast-path for non-sensitive repository code edits (opt-out control).
   * **Static ACL Rule:** Add fast-path `allow`, `ask`, or `deny` rule for `command(...)`, `write_file(...)`, `read_file(...)`, `read_url(...)`, or `mcp(...)`.
   * **Custom Semantic Guideline:** Add project-specific security rules (e.g. database migration protection, safe internal domains).
   * **Allowed Skill Paths:** Whitelist extra skill directory paths for sub-millisecond fast-path reads.

### Step 3: Sequential Conditional Branching

#### Branch A: If Permission Bundles was chosen:
1. List available bundles: `configure_permissions.py --list-bundles`.
2. Prompt user to select bundles to enable (`--enable-bundle`) or disable (`--disable-bundle`).

#### Branch B: If LLM Provider & Model was chosen:
1. **Turn 2 (Provider Selection):** Ask *only* for the provider protocol:
   - `Google Gemini` (Official Google REST API)
   - `Local / OpenAI-compatible` (Lemonade, vLLM, Ollama)
   - `Anthropic Claude` (Anthropic Messages API)

2. **Turn 3 (Provider-Specific Configuration):**
   * **If Google Gemini:**
     - Prompt for Gemini model (`gemini-2.5-flash` [Recommended], `gemini-2.5-pro`, `gemini-2.0-flash`).
     - Prompt for API key environment variable (default: `GEMINI_API_KEY`).
   * **If Local (Lemonade / vLLM / Ollama):**
     - Prompt for **Endpoint URL** (e.g. `http://localhost:13305/v1/chat/completions` for Lemonade, `http://localhost:11434/v1/chat/completions` for Ollama, `http://localhost:8000/v1/chat/completions` for vLLM).
     - Prompt for **Model Identifier** (e.g. `Gemma-4-26B-A4B-NoThinking-qat-MTP`, `gemma4-it-e4b-FLM`, `qwen2.5-coder`).
     - Prompt for **API Key Environment Variable** (e.g. `LEMONADE_API_KEY`, or optional/none for unauthenticated local servers).
   * **If Anthropic Claude:**
     - Prompt for Claude model (`claude-3-7-sonnet-20250219`, `claude-3-5-haiku-20241022`).
     - Prompt for **API Key Environment Variable** (e.g. `ANTHROPIC_API_KEY`).

#### Branch C: If Static ACL Rule was chosen:
1. Prompt for Decision bucket (`allow`, `ask`, `deny`).
2. Prompt for Resource rule string (e.g. `command(pytest -v)`, `command(git)`, `write_file(src/.*)`, `mcp(stripe:*)`).

#### Branch D: If Custom Semantic Guideline was chosen:
1. Prompt for natural language security guideline text (e.g. *"Treat internal requests to *.corp.internal as safe testing"*).

### Step 4: Apply Configuration & Validate
Execute `configure_permissions.py` with the collected flags, then verify with `auto-permissions-test`:
```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "run unit tests" --command "pytest -v" --markdown
```

---

## Direct CLI Usage Recipes

### 1. View Effective Configuration & Available Bundles
```bash
# View configuration status table
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list

# List all available built-in, global, and project bundles
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list-bundles

# Inspect a specific bundle's rules and documentation
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --bundle-info gh-readonly
```

### 2. Enable or Disable Permission Bundles

```bash
# Enable GitHub CLI read-only bundle and Python tooling bundle for the project
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --enable-bundle gh-readonly \
  --enable-bundle python-tooling

# Enable Rust tooling globally for all projects
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --enable-bundle rust-tooling

# Disable / override a globally enabled bundle in this specific project
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --disable-bundle rust-tooling
```

### 3. Migrate to Scoped Directory Layout
```bash
# Automatically migrate flat config files to .agents/auto-permissions/
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --migrate-layout
```

### 4. Configure LLM Provider & Model

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

### 5. Add Static ACL Rules (`allow`, `ask`, `deny`)

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

### 6. Add Custom Semantic Guidelines
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --add-guideline "Treat requests to internal endpoints *.corp.internal as safe testing operations."
```

### 7. Whitelist Allowed Skill Paths
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --add-skill-path "~/.nowledge-mem/skills-active"
```

### 8. Toggle Governed Tool Surfaces (Opt-In)
```bash
# Enable security gate classification for subagents
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --govern-subagents

# Disable governance for schedule (restore fast-path allow)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --no-govern-schedule
```

### 9. Toggle Security Gate Summary Disclosure (Opt-Out)
```bash
# Disable turn-scoped security gate summary disclosure in final responses
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --no-show-turn-summary

# Re-enable turn-scoped security gate summary disclosure (default)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --show-turn-summary
```

### 10. Configure Classifier Timeout
```bash
# Set project-scoped classifier timeout to 8.0s (for high-latency networks)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --timeout 8.0

# Set global classifier timeout to 6.0s (default)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --timeout 6.0
```

---

## Step 3: Validate with `auto-permissions-test`

After applying a customization, verify it with `auto-permissions-test`:
```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "run unit tests" --command "pytest -v" --markdown
```
