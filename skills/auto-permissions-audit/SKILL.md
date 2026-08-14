---
name: auto-permissions-audit
description: >-
  Inspect and summarize auto-permissions security classifier audit records, verify gate decisions (allow, deny, ask), and troubleshoot classification latency or failure states from session audit logs.
---

# Auto-Permissions Audit & Diagnostics Skill

Use this skill when the user asks to inspect permission audit logs, check auto-approval stats, or diagnose why a particular tool call was approved, blocked, or escalated.

## Procedures

### 1. Inspect Active Session Audit Log

Run the inspection script pointing to the active session's `audit.jsonl`:

```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_audit.jsonl>
```

To render the output as a collapsible Markdown table:
```bash
python3 skills/auto-permissions-audit/scripts/view_audit.py <path_to_audit.jsonl> --markdown
```

### 2. Live Log Query with jq / ripgrep

Find all blocked actions:
```bash
grep '"decision": "deny"' <path_to_audit.jsonl>
```

Find all high-latency classification calls (>1000ms):
```bash
grep -E '"latency_ms": [1-9][0-9]{3}' <path_to_audit.jsonl>
```

### 3. Verify Gemini Classifier Health

Execute a test classification with mock inputs:
```bash
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"pytest"}},"workspacePaths":["/tmp"],"stepIdx":0}' | python3 hooks/auto_approve_gate.py
```
