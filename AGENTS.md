# AGENTS.md

Welcome to the **`auto-permissions`** codebase. This repository implements an autonomous security authorization and auto-permission classifier plugin for Google Antigravity 2.0.

When working in this repository, all AI agents and subagents must strictly adhere to the instructions, guidelines, and operational invariants defined below.

---

## 1. Project Invariants & Core Architecture

1. **Zero External Runtime Dependencies:**
   - The core hook scripts (`hooks/auto_approve_gate.py`, `hooks/classifier.py`, `hooks/transcript_parser.py`, `hooks/audit_logger.py`) must run using **only the Python 3 standard library** (`urllib.request`, `json`, `os`, `sys`, `threading`, `time`).
   - Do NOT introduce dependencies on third-party packages (e.g. `requests`, `aiohttp`, `pydantic`) for the runtime hook execution. This ensures zero startup overhead and compatibility across all client environments.

2. **The Decoupled Classifier Principle:**
   - Never inject the agent's internal chain-of-thought (CoT), reasoning steps, or untrusted previous tool outputs into the classifier prompt payload.
   - The classifier prompt must contain **only** sanitized `<workspace_roots>`, `<prior_user_prompts>`, `<active_user_prompt>`, and `<proposed_tool_call>`.

3. **Fail-Closed Safety Contract:**
   - Any runtime exception, timeout (>4s), network error, or missing credentials must result in `{"decision": "ask", "reason": "Classifier fallback: ..."}`.
   - Never fail open or emit `allow` upon encountering errors.

4. **Non-Blocking Audit Logging:**
   - All audit writes must be non-blocking and rotatable (`max_bytes=5MB`, `backup_count=3`), appending atomic JSON Lines records to `<session_dir>/audit.jsonl`.

---

## 2. Directory Structure

```text
auto-permissions/
├── LICENSE                                  # MIT License
├── pyproject.toml                           # uv project & tool configuration (Ruff, pytest)
├── .python-version                          # Pinned interpreter version (3.14)
├── uv.lock                                  # Deterministic dependency lockfile
├── plugin.json                              # Plugin manifest (version, author, description)
├── hooks.json                               # PreToolUse lifecycle hook declaration
├── .pre-commit-config.yaml                  # Pre-commit git hooks configuration
├── release-please-config.json               # Release Please automation config
├── .release-please-manifest.json            # Release Please package versions
├── .github/
│   ├── dependabot.yml                       # Weekly grouped dependency & actions updater
│   └── workflows/
│       ├── ci.yml                           # Matrix testing, linting, and hook validation
│       └── release.yml                      # Automated semantic versioning & release PRs
├── .contrib/
│   └── package_plugin.py                    # Release packaging & artifact builder
├── .agents/
│   └── auto-permissions.json               # Project-level static ACL policy grants
├── hooks/
│   ├── __init__.py                          # Hooks package init
│   ├── auto_approve_gate.py                 # Main PreToolUse entrypoint
│   ├── pre_invocation.py                    # PreInvocation dynamic summary injector
│   ├── policy_engine.py                     # Fast-path static policy evaluation & scoping
│   ├── classifier.py                        # Gemini REST API security classifier
│   ├── transcript_parser.py                 # Backwards parser for user prompt history
│   └── audit_logger.py                      # Async rotatable JSONL audit logger
├── rules/
│   └── auto_permissions.md                  # Workspace rules for the agent
├── skills/
│   ├── auto-permissions-configure/
│   │   ├── SKILL.md                         # Interactive policy & provider configuration
│   │   └── scripts/
│   │       └── configure_permissions.py    # Policy configuration CLI
│   ├── auto-permissions-audit/
│   │   ├── SKILL.md                         # Audit inspection instructions
│   │   └── scripts/
│   │       └── view_audit.py                # Audit log reader CLI
│   ├── auto-permissions-fix/
│   │   ├── SKILL.md                         # ACL rule generator from denials (policy remediation)
│   │   └── scripts/
│   │       └── fix_permissions.py          # Policy rule fixer CLI
│   └── auto-permissions-test/
│       ├── SKILL.md                         # Policy & classifier simulation procedure
│       └── scripts/
│           └── test_permission.py          # Classifier simulation CLI
├── docs/
│   └── architecture.md                      # Comprehensive design specification
├── tests/
│   ├── test_configure_skill.py              # Unit tests for policy configuration skill
│   ├── test_transcript_parser.py            # Unit tests for transcript parser
│   ├── test_audit_logger.py                 # Unit tests for audit log & rotation
│   ├── test_classifier.py                   # Unit tests for multi-provider classifier
│   ├── test_policy_engine.py                # Unit tests for static ACL policy engine
│   ├── test_pre_invocation.py               # Unit tests for PreInvocation hook
│   ├── test_fix_permissions.py              # Unit tests for policy remediation rule derivation
│   ├── test_permission_skill.py             # Unit tests for test_permission simulation CLI
│   └── test_gate_e2e.py                     # End-to-end hook simulation tests
├── README.md                                # General project documentation
└── AGENTS.md                                # This file
```

---

## 3. Agent Operating Instructions

### 3.1 Handling Security Gate Feedback
* **`soft_deny` (Scope Deviation):** If a tool action is blocked by the gate with a `Security Gate (Scope Deviation): ...` message, the agent must treat this as an immediate self-correction signal.
  - Do NOT repeatedly invoke the exact same rejected tool call.
  - Re-examine the active user prompt and previous user turns. Adjust the approach to operate strictly within the user's requested boundaries, or ask the user for clarification if the action was intentional.
* **`hard_deny` (Security Gate Block):** If a tool action is blocked with `Security Gate Block: ...`, it violated core security policies (e.g. key extraction, exfiltration, destructive wipes). The agent must permanently cease the prohibited action.

### 3.2 Environment & Tooling Invariants
* **`uv` Execution Standard:** All Python commands, scripts, linters, and test runners must be executed via `uv run` (e.g. `uv run pytest`, `uv run ruff check .`), never bare `python3` or direct invocation of `.venv` paths.
* **Lockfile Integrity:** Any dependency modifications must be reflected in `pyproject.toml` and updated via `uv lock`. `uv.lock` must always remain clean and committed.
* **Pinned Interpreter:** `.python-version` specifies the required interpreter version to avoid drift across environments.

### 3.3 Multi-Agent Git Safety & Worktree Hygiene
In multi-agent workflows or shared git trees:
* **Prohibited Commands:** Never run destructive git commands like `git stash`, `git checkout --`, `git clean`, `git reset`, or branch switching.
* **Safe Inspection:** If you need to inspect committed file states without disturbing uncommitted modifications, use `git show HEAD:<path>`.

---

## 4. Developer Workflow & Test Standards

### Running Automated Tests
Run tests via `uv`:
```bash
uv run pytest -v
```

### Static Analysis & Formatting
Verify linting and code formatting:
```bash
uv run ruff check .
uv run ruff format --check .
```

### Manual Testing with Mock Stdin
To test the hook entrypoint directly:
```bash
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"pytest -v"}},"workspacePaths":["/tmp"],"stepIdx":0}' | python3 hooks/auto_approve_gate.py
```

### Inspecting Audit Logs
```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py /tmp/test_audit/audit.jsonl
```

---

## 5. Code Style & Commit Conventions

- **Ruff Standards:** Code must strictly pass `uv run ruff check .` (rules: `E`, `W`, `F`, `I`, `B`, `UP`, `SIM`, `N`) and `uv run ruff format --check .` (max line length: 100).
- **Clean Exception Handling (B110):** Silent exceptions in cleanup routines must use `contextlib.suppress(...)` rather than bare `pass`.
- **Status Quo Comments:** Comments describe the current active state only. Never include historical narratives ("changed from X") or self-evident line paraphrasing.
- **Conventional Commits:** Use standard Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`). Summary-only by default; descriptions must focus on the "why" and "what".
