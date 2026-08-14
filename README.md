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
4. **Audit2Allow Policy Generator (`auto-permissions-fix`):**
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

### Global Scope (Recommended)
Clone the repository directly into your global Antigravity plugins directory:
```bash
git clone https://github.com/abn/google-antigravity-plugin-auto-permissions ~/.gemini/config/plugins/auto-permissions
```

### Workspace-Specific Scope
Alternatively, clone directly into an individual workspace's `.agents/plugins/` directory:
```bash
git clone https://github.com/abn/google-antigravity-plugin-auto-permissions <your-workspace>/.agents/plugins/auto-permissions
```

### Prerequisites
Set your Gemini API key:
```bash
export GEMINI_API_KEY="your-api-key"
```

---

## Included Skills & Minimal Usage Examples

This plugin includes two specialized skills accessible via chat commands or standalone CLI scripts:

### 1. `/auto-permissions-audit` (Audit & Inspection)
Inspects session audit traces, decision breakdowns, latency metrics, and failure states.

* **View human-readable summary of the active session:**
  ```bash
  python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_audit.jsonl>
  ```
* **Render as a compact, collapsible Markdown table:**
  ```bash
  python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_audit.jsonl> --markdown
  ```

---

### 2. `/auto-permissions-fix` (SELinux `audit2allow` for Antigravity)
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
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py --rule "command(uv lock)" --allow --scope project
  ```
* **Interactive Mode (browse all recent denials and select scope interactively):**
  ```bash
  python3 skills/auto-permissions-fix/scripts/fix_permissions.py
  ```

---

## Directory Structure

```text
auto-permissions/
├── LICENSE                                  # MIT License
├── plugin.json                              # Manifest metadata
├── hooks.json                               # Lifecycle hook configuration
├── pyproject.toml                           # uv project and test configuration
├── .agents/
│   └── auto-permissions.json               # Project-level static ACL policy grants
├── hooks/
│   ├── auto_approve_gate.py                 # Main PreToolUse entrypoint
│   ├── pre_invocation.py                    # PreInvocation dynamic summary injector
│   ├── policy_engine.py                     # Fast-path static policy evaluation & scoping
│   ├── classifier.py                        # Gemini REST API security classifier
│   ├── transcript_parser.py                 # Token-efficient user prompt extractor
│   └── audit_logger.py                      # Async rotatable JSONL audit logger
├── rules/
│   └── auto_permissions.md                  # Agent operational guidance rule
├── skills/
│   ├── auto-permissions-audit/
│   │   ├── SKILL.md                         # Audit inspection procedure
│   │   └── scripts/
│   │       └── view_audit.py                # Audit log summary CLI
│   └── auto-permissions-fix/
│       ├── SKILL.md                         # ACL rule generator from denials (audit2allow)
│       └── scripts/
│           └── fix_permissions.py          # Policy rule fixer CLI
├── docs/
│   └── architecture.md                      # Comprehensive technical architecture
└── tests/
    ├── test_transcript_parser.py
    ├── test_audit_logger.py
    ├── test_classifier.py
    ├── test_policy_engine.py
    ├── test_pre_invocation.py
    ├── test_fix_permissions.py
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
