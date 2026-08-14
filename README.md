# Google Antigravity Plugin: Auto-Permissions Security Moderator

An autonomous security authorization and auto-permission classifier plugin for **Google Antigravity 2.0**, emulating Claude Code's Auto-Mode security moderator.

The plugin intercepts sensitive tool operations (commands, file writes, web requests, task management) via Antigravity's `PreToolUse` lifecycle hook, provides strictly sanitized contextual intent to a decoupled **Gemini 2.5 Flash** classifier, automatically approves safe actions, blocks hostile or out-of-scope operations, and records asynchronous rotatable audit logs in the active session directory.

---

## Key Features

1. **Decoupled Security Classifier:**
   - Evaluates tool operations independently of the agent's internal chain-of-thought (CoT) and previous tool outputs to eliminate indirect prompt injection (IPI) attack surfaces.
2. **Token-Efficient Multi-Turn History:**
   - Extracts prior user prompts from `transcript.jsonl` to resolve referential commands (e.g. *"Proceed"*, *"Run it again"*, *"Delete that migration file"*) while maintaining a minimal token footprint.
3. **Hierarchical Fast-Path Static ACL Engine:**
   - Evaluates static permission rules (`command(...)`, `write_file(...)`, `read_url(...)`) across **Session**, **Project** (`.agents/auto-permissions.json`), and **Global** scopes with strict `Deny > Ask > Allow` priority.
   - Matching static rules execute with **sub-millisecond latency (0ms)** with zero API cost.
4. **Denial Remediation & Policy Rule Generator (`auto-permissions-fix`):**
   - Automatically translates denials in `audit.jsonl` into candidate Antigravity ACL rules and writes them to Session, Project, or Global scopes.
5. **End-of-Round Collapsible Security Gate Summary:**
   - Appends a non-intrusive, collapsible Markdown summary table at the end of each round showing evaluated actions, verdicts (`🟢 ALLOW`, `🔴 DENY`, `🟡 ASK`), and evaluation modes (`Static ACL` vs `Gemini`).
6. **Four-Tier Decision Taxonomy:**
   - **`allow`**: Safe, intent-aligned workspace operations execute seamlessly without human friction.
   - **`soft_deny`**: Unrequested or scope-divergent actions are blocked, triggering the agent's *Deny-and-Continue* self-correction loop.
   - **`ask`**: Risky actions (production deployments, database migrations, cloud edits) are escalated to explicit interactive user confirmation.
   - **`hard_deny`**: Hostile actions (credential access, data exfiltration, transcript tampering, destructive deletions) are permanently blocked.
7. **Rotatable Asynchronous Audit Logging:**
   - Automatically records full execution traces to `<session_dir>/audit.jsonl` with size-based rotation.
8. **Zero External Python Dependencies:**
   - Uses Python standard library only (`urllib.request`, `json`, `os`, `sys`, `re`, `threading`).

---

## Installation & Setup

### Option 1: One-Shot Release Download (Recommended)
Download and extract the latest release artifact directly into your plugin directory in one shot, automatically creating parent directories and overwriting existing files:

```bash
# Global Scope (Recommended)
mkdir -p ~/.gemini/config/plugins/auto-permissions && \
curl -sL https://github.com/abn/google-antigravity-plugin-auto-permissions/releases/latest/download/auto-permissions.tar.gz | \
tar -xz -C ~/.gemini/config/plugins/auto-permissions --strip-components=1 --overwrite

# Workspace-Specific Scope
mkdir -p .agents/plugins/auto-permissions && \
curl -sL https://github.com/abn/google-antigravity-plugin-auto-permissions/releases/latest/download/auto-permissions.tar.gz | \
tar -xz -C .agents/plugins/auto-permissions --strip-components=1 --overwrite
```

### Option 2: Git Clone
Alternatively, clone the repository directly if you prefer tracking git commits:

```bash
# Global Scope
git clone https://github.com/abn/google-antigravity-plugin-auto-permissions ~/.gemini/config/plugins/auto-permissions

# Workspace-Specific Scope
git clone https://github.com/abn/google-antigravity-plugin-auto-permissions <your-workspace>/.agents/plugins/auto-permissions
```

### Prerequisites
Set your Gemini API key:
```bash
export GEMINI_API_KEY="your-api-key"
```

---

## Architecture & Design Specification

For complete details on the security principles, decoupled classifier blinding mechanics, threat modeling, state machine taxonomy, and latency benchmarks, see the **[Architecture & Technical Design Specification](docs/architecture.md)**.

---

## Included Skills & Minimal Usage Examples

This plugin includes four specialized skills accessible via chat commands or standalone CLI scripts:

### 1. `/auto-permissions-configure` (Interactive Policy & Provider Setup)
Guides users through configuring static ACL rules, custom semantic guidelines, LLM providers (Google, local Lemonade/vLLM/Ollama, Anthropic), endpoints, and skill paths across Session, Project, or Global scopes.

* **Inspect active configuration across all scopes:**
  ```bash
  python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list
  ```
* **Set project-level static allow rule:**
  ```bash
  python3 skills/auto-permissions-configure/scripts/configure_permissions.py --scope project --add-rule "command(pytest -v)" --decision allow
  ```
* **Configure local GPU inference (Lemonade / vLLM):**
  ```bash
  python3 skills/auto-permissions-configure/scripts/configure_permissions.py --scope project_local --provider openai --model Gemma-4-26B-A4B-NoThinking-qat-MTP --endpoint-url "http://localhost:13305/v1/chat/completions" --api-key-env LEMONADE_API_KEY
  ```
* **Add a custom semantic guideline:**
  ```bash
  python3 skills/auto-permissions-configure/scripts/configure_permissions.py --scope project --add-guideline "Treat requests to *.corp.internal as safe testing operations."
  ```

---

### 2. `/auto-permissions-audit` (Audit & Inspection)
Inspects session audit traces, decision breakdowns, latency metrics, and failure states.

* **Inspect active session audit log:**
  ```bash
  python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_session_audit.jsonl>
  ```
* **Run automated issue diagnosis & prescriptive recommendations:**
  ```bash
  python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_session_audit.jsonl> --diagnose
  ```
* **Render compact Markdown summary:**
  ```bash
  python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_session_audit.jsonl> --markdown
  ```

### 3. `auto-permissions-fix` (Denial Remediation & Rule Generator)
Parses denials from `audit.jsonl` and generates persistent ACL grants across Session, Project, or Global scopes.

* **Auto-allow the most recent denied action in the current session:**
  ```bash
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --last --allow --scope session
  ```
* **Auto-allow the most recent denied action for the whole repository (`.agents/auto-permissions.json`):**
  ```bash
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --last --allow --scope project
  ```
* **Add an explicit custom rule directly:**
  ```bash
  # Allow dependency sync in project:
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "command(uv lock)" --allow --scope project

  # Fast-path whitelist git commands for the project:
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "command(git)" --allow --scope project

  # Fast-path whitelist GitHub CLI globally:
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "command(gh)" --allow --scope global
  ```
* **Interactive Mode (browse all recent denials and select scope interactively):**
  ```bash
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py
  ```

---

### 4. `auto-permissions-test` (Policy & Classifier Simulation)
Simulates how the security classifier and static policies would evaluate a hypothetical tool call against a given user prompt before executing it, rendering collapsible input/output traces.

* **Test a command against a user prompt (Markdown output with collapsible folds):**
  ```bash
  python3 skills/auto-permissions-test/scripts/test_permission.py "fix styling in style.css" --command "git push origin main" --markdown
  ```
* **Test file modifications:**
  ```bash
  python3 skills/auto-permissions-test/scripts/test_permission.py "refactor auth" --tool write_to_file --target src/auth.py --markdown
  ```
* **Output raw JSON:**
  ```bash
  python3 skills/auto-permissions-test/scripts/test_permission.py "run test suite" --command "pytest -v" --json
  ```

---

## Configuration: Providers, Endpoints & Static ACLs

You can configure project-level policies in `.agents/auto-permissions.json` (tracked) or `.agents/auto-permissions.local.json` (untracked local secrets/overrides, ignored by git), or globally in `~/.gemini/config/auto-permissions.json`:

```json
{
  "provider": "google",
  "model": "gemini-2.5-flash",
  "endpoint_url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
  "api_key_env": "GEMINI_API_KEY",
  "allow": [
    "command(uv lock)",
    "command(pytest -v)",
    "mcp(nowledge-mem:*)"
  ],
  "ask": [
    "command(git push .*)",
    "command(gh pr .*)",
    "mcp(stripe:*)"
  ],
  "deny": [
    "write_file(.github/workflows/.*)",
    "mcp(*:delete_*)"
  ],
  "custom_guidelines": [
    "Treat requests to internal endpoints *.corp.internal as safe testing operations.",
    "Require explicit confirmation before modifying database migrations under migrations/."
  ],
  "allowed_skill_paths": [
    "~/.nowledge-mem/skills-active"
  ]
}
```

### Multi-Provider & Local Inference Support

`auto-permissions` supports Google Gemini, OpenAI-compatible servers (e.g. local Lemonade, vLLM, Ollama, Groq, OpenRouter), and Anthropic Claude using zero external dependencies:

```json
// Example: Local Self-Hosted LLM on GPU (Lemonade / vLLM / Ollama)
{
  "provider": "openai",
  "model": "gemma-2-9b-it",
  "endpoint_url": "http://localhost:8000/v1/chat/completions",
  "api_key": "optional-local-token"
}
```

### Complete Configuration Levers Reference

#### 1. JSON Policy Configuration Levers (`auto-permissions.json`, `auto-permissions.local.json`, `session_overrides.json`)

| Configuration Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `provider` | `string` | `"google"` | Classification provider/protocol (`"google"`, `"openai"`, `"anthropic"`). |
| `model` | `string` | `"gemini-2.5-flash"` | Target LLM model name (e.g. `gemini-2.5-flash`, `gpt-4o-mini`, `claude-3-5-haiku-20241022`). |
| `endpoint_url` | `string` | *Provider default* | Custom REST API endpoint URI (e.g. local vLLM/Lemonade/Ollama or reverse proxy). |
| `api_key` | `string` | `null` | Direct API token string (recommended only in `.agents/auto-permissions.local.json`). |
| `api_key_env` | `string` | *Provider default* | Name of custom environment variable holding the API key. |
| `allow` | `array[string]` | `[]` | Static ACL rules auto-approved in `0.1ms` without invoking LLM classifier. |
| `ask` | `array[string]` | `[]` | Static ACL rules forcing interactive human prompt in `0.1ms`. |
| `deny` | `array[string]` | `[]` | Static ACL rules blocked in `0.1ms` (highest priority). |
| `custom_guidelines` | `array[string]` | `[]` | Semantic domain guidelines injected into the classifier prompt. |
| `allowed_skill_paths` | `array[string]` | `[]` | Extra directory roots permitted for safe `0.1ms` skill file reads. |
| `govern_subagents` | `boolean` | `false` | When `true`, intercepts `invoke_subagent` and evaluates via classifier. |
| `govern_schedule` | `boolean` | `false` | When `true`, intercepts `schedule` (cron/timers) and evaluates via classifier. |
| `govern_images` | `boolean` | `false` | When `true`, intercepts `generate_image` and evaluates via classifier. |
| `govern_surfaces` | `array[string]` | `[]` | Array alias for toggling governed surfaces (`["subagents", "schedule", "images"]`). |

#### 2. Environment Variable Levers

| Environment Variable | Default | Purpose |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | - | Primary API key for Google Gemini provider. |
| `OPENAI_API_KEY` | - | API key for OpenAI-compatible endpoints. |
| `ANTHROPIC_API_KEY` | - | API key for Anthropic Claude provider. |
| `AUTO_PERMISSIONS_API_KEY` | - | Generic provider API key override. |
| `AUTO_PERMISSIONS_PROVIDER` | - | Override active provider globally (`google`, `openai`, `anthropic`). |
| `AUTO_PERMISSIONS_MODEL` | - | Override active model identifier globally (or `GEMINI_MODEL`, `OPENAI_MODEL`, `ANTHROPIC_MODEL`). |
| `AUTO_PERMISSIONS_ENDPOINT_URL` | - | Override custom REST endpoint globally (or `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`). |
| `AUTO_PERMISSIONS_TIMEOUT` | `4.0` | HTTP classifier timeout in seconds. Increase for large local LLMs (e.g. `60.0`). |
| `AUTO_PERMISSIONS_GOVERN_SUBAGENTS` | `0` | Set `1` to enable classifier evaluation for `invoke_subagent`. |
| `AUTO_PERMISSIONS_GOVERN_SCHEDULE` | `0` | Set `1` to enable classifier evaluation for `schedule`. |
| `AUTO_PERMISSIONS_GOVERN_IMAGES` | `0` | Set `1` to enable classifier evaluation for `generate_image`. |
| `AUTO_PERMISSIONS_GOVERN_SURFACES` | - | Comma-separated list of surfaces to govern (e.g. `subagents,schedule,images`). |
| `AUTO_PERMISSIONS_SESSION_DIR` | - | Override session directory path for audit logs and overrides (or `ANTIGRAVITY_ARTIFACT_DIR`). |

---

## Directory Structure

```text
auto-permissions/
├── LICENSE                                  # MIT License
├── plugin.json                              # Manifest metadata
├── hooks.json                               # Lifecycle hook configuration
├── pyproject.toml                           # uv project and test configuration
├── .agents/
│   ├── auto-permissions.json               # Project-level static ACL policy grants (tracked)
│   └── auto-permissions.local.json         # Local untracked secrets & overrides (gitignored)
├── hooks/
│   ├── auto_approve_gate.py                 # Main PreToolUse entrypoint
│   ├── pre_invocation.py                    # PreInvocation dynamic summary injector
│   ├── policy_engine.py                     # Fast-path static policy evaluation & scoping
│   ├── classifier.py                        # Multi-provider security classifier
│   ├── transcript_parser.py                 # Token-efficient user prompt extractor
│   └── audit_logger.py                      # Async rotatable JSONL audit logger
├── rules/
│   └── auto_permissions.md                  # Agent operational guidance rule
├── skills/
│   ├── auto-permissions-configure/
│   │   ├── SKILL.md                         # Interactive policy & provider configuration
│   │   └── scripts/
│   │       └── configure_permissions.py    # Policy configuration CLI
│   ├── auto-permissions-audit/
│   │   ├── SKILL.md                         # Audit inspection procedure
│   │   └── scripts/
│   │       └── view_audit.py                # Audit log summary CLI
│   ├── auto-permissions-fix/
│   │   ├── SKILL.md                         # ACL rule generator from denials (policy remediation)
│   │   └── scripts/
│   │       └── fix_permissions.py          # Policy rule fixer CLI
│   └── auto-permissions-test/
│       ├── SKILL.md                         # Policy & classifier simulation procedure
│       └── scripts/
│           └── test_permission.py          # Classifier simulation CLI
├── docs/
│   └── architecture.md                      # Comprehensive technical architecture
└── tests/
    ├── test_configure_skill.py
    ├── test_transcript_parser.py
    ├── test_audit_logger.py
    ├── test_classifier.py
    ├── test_policy_engine.py
    ├── test_pre_invocation.py
    ├── test_fix_permissions.py
    ├── test_permission_skill.py
    └── test_gate_e2e.py
```

---

## Running Tests & Static Analysis

Run the automated test suite with `uv`:
```bash
uv run pytest -v
```

Verify formatting and linting:
```bash
uv run ruff check .
uv run ruff format --check .
```

---

## Security Layers: Plugin Gate vs. Platform Container Sandbox

Google Antigravity enforces security across two distinct layers:

```text
[ Proposed Tool Call ]
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: auto-permissions Plugin Gate (Intent Authorization)│
│  - Evaluates user prompt vs proposed tool action.           │
│  - Emits: allow, ask, or deny.                              │
└────────────────────────┬────────────────────────────────────┘
                         │ (allow)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Antigravity Container Sandbox (System Isolation)   │
│  - Sandboxed (BypassSandbox: false): Workspace isolated,    │
│    .git/ mounted as read-only.                              │
│  - Unsandboxed (BypassSandbox: true): Required for commands │
│    writing to .git/ (git commit, git merge, git checkout).  │
│  - Triggers host platform confirmation modal.               │
└─────────────────────────────────────────────────────────────┘
```

### Why does `git commit` trigger a host prompt even if the plugin auto-approves it?
1. The **`auto-permissions` gate (Layer 1)** checks your prompt and auto-approves the commit because you explicitly requested it.
2. The **Antigravity container sandbox (Layer 2)** protects `.git/` by mounting it read-only.
3. When git commands write to `.git/`, the tool must run unsandboxed (`BypassSandbox: true`), which causes the **Antigravity host IDE** to display an interactive platform modal.

### How to Mitigate
* When the Antigravity Sandbox bypass modal appears for `git commit`, click **"Always allow for this workspace"**.
* This whitelists unsandboxed execution for that command pattern in your workspace, allowing subsequent commits to run completely unattended.

---

## License

This project is licensed under the [MIT License](LICENSE).
