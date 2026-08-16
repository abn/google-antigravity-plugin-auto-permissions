---
okf_version: "0.2"
type: "guide"
title: "Audit Inspection & Policy Remediation"
description: "How to inspect audit logs, troubleshoot classification latency, and automatically generate scoped ACL rules from security gate denials."
category: "guides"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "code-analysis"
  verified:
    tier: "test_suite"
    date: "2026-08-16"
sources:
  - "hooks/audit_logger.py"
  - "skills/auto-permissions-audit/scripts/view_audit.py"
  - "skills/auto-permissions-fix/scripts/fix_permissions.py"
stale_after: "2027-08-16"
tags:
  - "audit"
  - "remediation"
  - "logging"
  - "troubleshooting"
---

# Audit Inspection & Policy Remediation

The `auto-permissions` plugin maintains a non-blocking, rotatable audit trail for every intercepted tool call, providing observability into why actions were allowed, denied, or escalated.

---

## 1. Inspecting the Session Audit Log

Audit records are stored as atomic JSON Lines in `<session_dir>/auto-permissions/audit.jsonl`.

### Using the Audit Viewer CLI

```bash
# View active session audit summary
python3 skills/auto-permissions-audit/scripts/view_audit.py

# Filter for denials and escalations only
python3 skills/auto-permissions-audit/scripts/view_audit.py --status deny,ask
```

Output:
```text
🛡️ Auto-Permissions Audit Log (14 events):
================================================================================
[09:15:22] 🟢 ALLOW  run_command (git status)              [Static ACL / 0.2ms]
[09:15:24] 🟢 ALLOW  run_command (pytest -v)               [bundle:python-tooling / 0.3ms]
[09:15:40] 🟡 ASK    run_command (git push origin main)    [Gemini 2.5 Flash / 1420ms]
[09:16:01] 🔴 DENY   run_command (git reset --hard)        [Gemini 2.5 Flash / 1380ms]
                     └─ Scope Deviation: destructive reset unauthorized
```

---

## 2. Automated Policy Remediation (`auto-permissions-fix`)

When legitimate commands are soft-denied or escalated, use the remediation fixer to convert audit denials into persistent ACL rules:

```bash
# Inspect denied events and suggest rules
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --preview

# Apply suggested rules to project scope
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --scope project --apply
```
