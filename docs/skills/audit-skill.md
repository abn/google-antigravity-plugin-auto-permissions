---
okf_version: "0.2"
type: "guide"
title: "Auto-Permissions Audit Skill Guide"
description: "Instructions for inspecting audit logs, analyzing gate decisions, and diagnosing classifier latency."
category: "skills"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "code-analysis"
  verified:
    tier: "test_suite"
    date: "2026-08-16"
sources:
  - "skills/auto-permissions-audit/SKILL.md"
stale_after: "2027-08-16"
tags:
  - "skills"
  - "audit"
  - "observability"
---

# Auto-Permissions Audit Skill Guide

The `auto-permissions-audit` skill inspects active session audit records and renders structured decision logs.

---

## Capabilities

1. **Session Timeline Analysis:** Displays chronological tool call events, decisions, and latencies.
2. **Denial & Fallback Filtering:** Isolates blocked actions, scope deviations, and timeout events.
3. **Performance Metrics:** Aggregates static vs classifier latencies and p95 trends.

---

## Direct CLI Usage

```bash
# View full active session log
python3 skills/auto-permissions-audit/scripts/view_audit.py

# Inspect specific audit file
python3 skills/auto-permissions-audit/scripts/view_audit.py /path/to/audit.jsonl
```
