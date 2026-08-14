---
name: auto-permissions-audit
description: >-
  Inspect and summarize auto-permissions security classifier audit records, verify gate decisions (allow, deny, ask), and troubleshoot classification latency or failure states from session audit logs.
---

# Auto-Permissions Audit & Diagnostics Skill

Use this skill when the user asks to inspect permission audit logs, check auto-approval stats, diagnose why a particular tool call was approved, blocked, or escalated, or troubleshoot security gate behavior.

## Crucial Operational Rule: Session Bounded Inspection
* The agent must **ONLY** attempt to inspect the active session's audit log: `<session_dir>/audit.jsonl` (or `<artifactDirectoryPath>/audit.jsonl`).
* **NEVER** search frantically across `/tmp`, other workspaces, or parent directories if the file is absent.
* If `<session_dir>/audit.jsonl` does not exist or contains 0 records, immediately report to the user:
  > *"No audit records found for this session (`<session_dir>/audit.jsonl`). The security gate has not evaluated any tool actions in this session yet."*

---

## Procedures

### 1. Inspect Active Session Audit Log & Run Diagnostics

Run the inspection script against the active session's `audit.jsonl`:

```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_active_session_audit.jsonl>
```

To render the output as a compact collapsible Markdown summary table:
```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_active_session_audit.jsonl> --markdown
```

To run detailed issue diagnosis and receive prescriptive ACL recommendations:
```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_active_session_audit.jsonl> --diagnose
```

---

### 2. Live Query with jq / ripgrep (Targeted Session File Only)

Find all blocked actions in the session log:
```bash
grep '"decision": "deny"' <path_to_active_session_audit.jsonl>
```

Find high-latency classification calls (>1500ms):
```bash
grep -E '"latency_ms": [1-9][0-9]{3}' <path_to_active_session_audit.jsonl>
```

---

### 3. Verify Gemini Classifier Health

Execute a test classification with mock inputs to verify API connectivity and response format:
```bash
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"pytest"}},"workspacePaths":["/tmp"],"stepIdx":0}' | python3 hooks/auto_approve_gate.py
```
