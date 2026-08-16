---
okf_version: "0.2"
type: "guide"
title: "Auto-Permissions Fix Skill Guide"
description: "Instructions for converting security gate denials into persistent scoped ACL rules."
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
  - "skills/auto-permissions-fix/SKILL.md"
stale_after: "2027-08-16"
tags:
  - "skills"
  - "remediation"
  - "fix"
---

# Auto-Permissions Fix Skill Guide

The `auto-permissions-fix` skill scans audit log denials and auto-generates precise static ACL rules.

---

## Workflow

1. **Denial Discovery:** Scans the active session audit log for `deny` and `ask` records.
2. **Rule Synthesis:** Synthesizes `command(...)` pattern rules.
3. **Interactive Review:** Displays the proposed rules with target scopes (Session, Project Local, Project, Global).
4. **Application:** Persists the rules to the target scope file.

---

## Direct CLI Recipes

```bash
# Preview suggested rules from recent denials
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --preview

# Apply suggested rules to project configuration
python3 skills/auto-permissions-fix/scripts/fix_permissions.py --scope project --apply
```
