# Google Antigravity Plugin: Auto-Permissions Security Moderator

An autonomous security authorization and auto-permission classifier plugin for **Google Antigravity 2.0**, emulating Claude Code's Auto-Mode security moderator.

The plugin intercepts sensitive tool operations (commands, file writes, web requests, task management) via Antigravity's `PreToolUse` lifecycle hook, provides strictly sanitized contextual intent to a decoupled **Gemini 2.5 Flash** classifier, automatically approves safe actions, blocks hostile or out-of-scope operations, and records asynchronous rotatable audit logs in the active session directory.

---

## Key Features

1. **Decoupled Security Classifier:**
   - Evaluates tool operations independently of the agent's internal chain-of-thought (CoT) and previous tool outputs to eliminate indirect prompt injection (IPI) attack surfaces.
2. **Token-Efficient Multi-Turn History:**
   - Extracts prior user prompts from `transcript.jsonl` to resolve referential commands (e.g. *"Proceed"*, *"Run it again"*, *"Delete that migration file"*) while maintaining a minimal token footprint.
3. **Sub-Millisecond Fast-Path Cascade (~0.1ms):**
   - Evaluates static permission rules (`command(...)`, `write_file(...)`, `read_url(...)`, `mcp(...)`) across **Session**, **Project (Local)**, **Project (Tracked)**, and **Global** scopes with strict `Deny > Ask > Allow` priority.
   - Automatically auto-approves safe workspace file edits (`trust_workspace_writes`), same-turn file mutations, safe read-only shell commands, and session artifact operations in **0.1ms** with zero API cost.
4. **Denial Remediation & Policy Rule Generator (`auto-permissions-fix`):**
   - Automatically translates denials in `audit.jsonl` into candidate Antigravity ACL rules and writes them to Session, Project, or Global scopes.
5. **Turn-Scoped Collapsible Security Gate Summary (with Opt-Out):**
   - Appends a clean, collapsible Markdown summary table at the bottom of the final response detailing evaluated actions, verdicts (`🟢 ALLOW`, `🔴 DENY`, `🟡 ASK`), and evaluation modes (`Static ACL`, `Gemini`, `Workspace Write`, `Session Artifact`).
   - Supports opt-out via `"show_turn_summary": false` / `--no-show-turn-summary` / `AUTO_PERMISSIONS_SHOW_TURN_SUMMARY=0`.
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

---

## Permission Bundles

**Permission Bundles** provide curated, reusable sets of static ACL rules, semantic guidelines, and skill whitelists that can be enabled with a single command or configuration entry. Instead of writing dozens of individual regex rules for standard tools, developers can activate domain-specific bundles.

### 1. Built-in Bundles Catalog

`auto-permissions` ships with 8 pre-packaged, zero-dependency built-in bundles:

| Bundle Slug | Domain / Tools | Included Rules & Capabilities |
| :--- | :--- | :--- |
| **`git-inspect`** | Git Inspection | Read-only repository inspection (`git status`, `log`, `diff`, `branch`, `show`, `tag`, `remote`, `rev-parse`, `describe`). |
| **`gh-readonly`** | GitHub CLI | Read-only GitHub queries (`gh pr view/list/checks/diff/status`, `run list/view`, `issue list/view`, `release list/view`, `repo view`). |
| **`python-tooling`** | Python Dev Tools | Safe Python testing, formatting, and packaging (`pytest`, `python -m pytest`, `uv run pytest`, `ruff check/format`, `black`, `flake8`, `mypy`, `uv lock`, `poetry`). |
| **`rust-tooling`** | Rust / Cargo | Standard Cargo build, test, and lint commands (`cargo test`, `check`, `clippy`, `fmt`, `doc`, `build`). |
| **`node-tooling`** | Node.js / Web | Common JavaScript/TypeScript testing and linting (`npm/pnpm/yarn/bun test/lint`, `eslint`, `prettier`). |
| **`container-inspect`** | Docker & Podman | Safe container status inspection (`podman/docker ps`, `logs`, `images`, `inspect`). |
| **`dev-docs-read`** | Web Documentation | Whitelisted read access to official documentation sites (`docs.python.org`, `developer.mozilla.org`, `readthedocs.io`, `pkg.go.dev`, `crates.io`, `docs.rs`, `npmjs.com`). |
| **`mcp-nmem`** | Nowledge Mem MCP | Read-only search, lookup, and memory query tools for Nowledge Mem. |

### 2. Enabling Bundles

Enable bundles via CLI:
```bash
# Enable in the active project (.agents/auto-permissions/config.json)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --enable-bundle git-inspect \
  --enable-bundle gh-readonly \
  --enable-bundle python-tooling

# Enable globally for all workspaces (~/.gemini/config/auto-permissions/config.json)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope global \
  --enable-bundle git-inspect
```

Or configure directly in your `config.json`:
```json
{
  "bundles": [
    "git-inspect",
    "gh-readonly",
    "python-tooling"
  ]
}
```

### 3. Disabling & Overriding Global Bundles in Projects

If a bundle is enabled globally, a specific project or session can mask or disable it:

```bash
# Disable rust-tooling in this specific project
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --disable-bundle rust-tooling
```

In `config.json`:
```json
{
  "bundles": {
    "enabled": ["python-tooling"],
    "disabled": ["rust-tooling"]
  }
}
```

### 4. Custom & Extensible Bundles

You can define custom bundles in three ways:

1. **Project Bundles:** Place JSON files in `.agents/auto-permissions/bundles/<name>.json` (tracked) or `.agents/auto-permissions/bundles.local/<name>.json` (local).
2. **Global Bundles:** Place JSON files in `~/.gemini/config/auto-permissions/bundles/<name>.json`.
3. **Inline Custom Bundles:** Define them directly under `"custom_bundles"` in `config.json`.

Custom bundles can extend existing bundles via `"extends"`:
```json
{
  "name": "custom-ci-tools",
  "description": "Custom testing suite combining Python and container tools",
  "extends": ["python-tooling", "container-inspect"],
  "allow": [
    "command(make test)",
    "command(docker compose ps)"
  ]
}
```

---

## Configuration: Providers, Endpoints & Scoped Layout

### Scoped Configuration Layout

`auto-permissions` uses a clean, encapsulated directory structure that prevents namespace collisions with other agent tools:

* **Project Tracked:** `.agents/auto-permissions/config.json` (committed to git, shared with team).
* **Project Local:** `.agents/auto-permissions/config.local.json` (gitignored, private tokens/endpoints).
* **Global:** `~/.gemini/config/auto-permissions/config.json` (applies to all user workspaces).
* **Session:** `<session_dir>/auto-permissions/session_overrides.json` (active turn/session overrides).

*(Note: Legacy flat filenames `.agents/auto-permissions.json` and `~/.gemini/config/auto-permissions.json` remain fully supported via backward-compatible fallback resolution).*

To automatically migrate an existing repository to the new scoped structure:
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --migrate-layout
```

### Configuration File Format (`config.json`)

```json
{
  "provider": "google",
  "model": "gemini-2.5-flash",
  "endpoint_url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
  "api_key_env": "GEMINI_API_KEY",
  "bundles": [
    "git-inspect",
    "gh-readonly",
    "python-tooling"
  ],
  "allow": [
    "command(uv lock)",
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

#### 1. JSON Policy Configuration Levers (`config.json`, `config.local.json`, `session_overrides.json`)

| Configuration Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `bundles` | `array[string]` or `object` | `[]` | Active permission bundles (`["git-inspect", ...]` or `{"enabled": [...], "disabled": [...]}`). |
| `custom_bundles` | `object` | `{}` | Inline custom bundle definitions dictionary. |
| `provider` | `string` | `"google"` | Classification provider/protocol (`"google"`, `"openai"`, `"anthropic"`). |
| `model` | `string` | `"gemini-2.5-flash"` | Target LLM model name (e.g. `gemini-2.5-flash`, `gpt-4o-mini`, `claude-3-5-haiku-20241022`). |
| `endpoint_url` | `string` | *Provider default* | Custom REST API endpoint URI (e.g. local vLLM/Lemonade/Ollama or reverse proxy). |
| `api_key` | `string` | `null` | Direct API token string (recommended only in `config.local.json`). |
| `api_key_env` | `string` | *Provider default* | Name of custom environment variable holding the API key. |
| `allow` | `array[string]` | `[]` | Static ACL rules auto-approved in `0.1ms` without invoking LLM classifier. |
| `ask` | `array[string]` | `[]` | Static ACL rules forcing interactive human prompt in `0.1ms`. |
| `deny` | `array[string]` | `[]` | Static ACL rules blocked in `0.1ms` (highest priority). |
| `custom_guidelines` | `array[string]` | `[]` | Semantic domain guidelines injected into the classifier prompt. |
| `allowed_skill_paths` | `array[string]` | `[]` | Extra directory roots permitted for safe `0.1ms` skill file reads. |
| `trust_workspace_writes` | `boolean` | `true` | When `true` (default), enables `0.1ms` fast-path for non-sensitive workspace writes. |
| `show_turn_summary` | `boolean` | `true` | When `true` (default), appends turn-scoped collapsible security gate summary table to final response. |
| `disclose_turn_summary` | `boolean` | `true` | Alias for `show_turn_summary`. |
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
| `AUTO_PERMISSIONS_TRUST_WORKSPACE_WRITES` | `1` | Override workspace write fast-path (`1`/`0` or `true`/`false`). |
| `AUTO_PERMISSIONS_SHOW_TURN_SUMMARY` | `1` | Override turn-scoped security gate disclosure table (`1`/`0` or `true`/`false`). |
| `AUTO_PERMISSIONS_DISCLOSE_TURN_SUMMARY` | `1` | Alias for `AUTO_PERMISSIONS_SHOW_TURN_SUMMARY`. |
| `AUTO_PERMISSIONS_TIMEOUT` | `6.0` | HTTP classifier timeout in seconds (or `AUTO_PERMISSIONS_TIMEOUT_SECS`). Configurable via policy files (`timeout`) or CLI. |
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
│   └── auto-permissions/
│       ├── config.json                      # Project-level static ACL grants & active bundles (tracked)
│       ├── config.local.json                # Local untracked secrets & overrides (gitignored)
│       ├── bundles/                         # Project-specific custom bundles (tracked)
│       └── bundles.local/                   # Project-specific local custom bundles (untracked)
├── hooks/
│   ├── bundles/                             # Built-in zero-dependency bundles
│   │   ├── __init__.py                      # Bundle loader and registry
│   │   ├── git_inspect.json                 # git-inspect bundle
│   │   ├── gh_readonly.json                 # gh-readonly bundle
│   │   ├── python_tooling.json              # python-tooling bundle
│   │   ├── rust_tooling.json                # rust-tooling bundle
│   │   ├── node_tooling.json                # node-tooling bundle
│   │   ├── container_inspect.json           # container-inspect bundle
│   │   ├── dev_docs_read.json               # dev-docs-read bundle
│   │   └── mcp_nmem.json                    # mcp-nmem bundle
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
    ├── test_bundles.py                      # Unit tests for permission bundles & resolution
    ├── test_configure_skill.py              # Unit tests for configure CLI
    ├── test_transcript_parser.py
    ├── test_audit_logger.py
    ├── test_classifier.py
    ├── test_policy_engine.py
    ├── test_pre_invocation.py
    ├── test_fix_permissions.py
    ├── test_permission_skill.py
    ├── test_package_plugin.py
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
