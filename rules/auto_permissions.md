---
name: auto-permissions
description: Auto-permissions security gate rules and operational guidelines for autonomous tool execution.
always_on: true
---

# Auto-Permissions Security Gate Rules

This workspace is protected by the **Auto-Permissions Classifier Plugin**, which emulates Claude Code's Auto-Mode security moderator.

## Operational Guidelines for the Agent

1. **Explicit Intent Alignment:**
   - Always operate strictly within the scope of the user's instructions and workspace boundaries.
   - Do not perform out-of-scope actions (such as deleting unrequested git branches, clearing system configs, or accessing external networks) without explicit user prompting.

2. **Handling `soft_deny` (Scope Deviation Blocks):**
   - If a tool call is blocked with `Security Gate (Scope Deviation): ...`, treat this as a self-correction signal.
   - Do not repeatedly attempt the exact same blocked action. Instead, explain the constraint to the user or ask for clarification/confirmation if the step was necessary.

3. **Handling `hard_deny` (Security Gate Blocks):**
   - If an action is blocked with `Security Gate Block: ...`, it violated core security policies (e.g. credential access, exfiltration, destruction). Cease the prohibited action immediately.

4. **Auditability:**
   - All tool classification decisions, raw prompts, latency, and verdicts are recorded in `<session_dir>/auto-permissions/audit.jsonl`.

5. **End-of-Round Security Gate Summary Table:**
   - At the conclusion of any round where state-changing or gated tool calls (`run_command`, `write_to_file`, `replace_file_content`, `read_url_content`, etc.) were evaluated, append a clean, collapsible Markdown summary table at the bottom of the final response to the user.
   - Do NOT append this summary to intermediate status messages or progress updates while waiting for background tasks or subagents:

```markdown
<details>
<summary>🛡️ <b>Security Gate Summary:</b> N actions evaluated (X allowed, Y denied)</summary>

| Tool Action | Target | Verdict | Mode / Reason |
| :--- | :--- | :---: | :--- |
| `replace_file_content` | `pyproject.toml` | 🟢 **ALLOW** | Safe workspace file edit |
| `run_command` | `uv lock` | 🟢 **ALLOW** | Static Project ACL (0.2ms) |
| `run_command` | `pytest -v` | 🟢 **ALLOW** | Gemini Classifier (340ms) |

</details>
```
