---
okf_version: "0.2"
type: "guide"
title: "Configuring Policies & 5-Tier Scoping Hierarchy"
description: "How to configure static ACL rules, semantic guidelines, timeout budgets, and model settings across Session, Project Local, Project, and Global scopes."
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
  - "hooks/policy_engine.py"
  - "skills/auto-permissions-configure/scripts/configure_permissions.py"
stale_after: "2027-08-16"
tags:
  - "configuration"
  - "scoping"
  - "rules"
  - "policy"
---

# Configuring Policies & 5-Tier Scoping Hierarchy

`auto-permissions` resolves configuration through a 5-tier inheritance hierarchy, allowing fine-grained control at global, repository, developer, and session levels.

---

## 1. The 5-Tier Scoping Hierarchy

```text
1. Session Scope        <session_dir>/auto-permissions/session_overrides.json
   ↓ (overrides)
2. Project Local Scope  <workspace>/.agents/auto-permissions/config.local.json (git-ignored)
   ↓ (overrides)
3. Project Scope        <workspace>/.agents/auto-permissions/config.json (tracked)
   ↓ (overrides)
4. Global Scope         ~/.gemini/config/auto-permissions/config.json
   ↓ (overrides)
5. Built-in Defaults    Zero-dependency defaults (hooks/bundles/*.json)
```

- **Static Precedence:** `Deny > Ask > Allow`. If any scope issues a `deny`, the action is blocked regardless of `allow` rules in lower scopes.
- **Inheritance Merging:** `custom_guidelines`, `allowed_skill_paths`, and `bundles` are merged top-down.

---

## 2. Using the Configuration CLI

The bundled CLI tool (`configure_permissions.py`) allows viewing and updating all settings:

### View Effective Configuration
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py
```

### Add Static ACL Rule to Repository
```bash
# Allow specific build command in Project scope
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --allow "command(cargo test --lib*)"

# Deny destructive push
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --deny "command(git push origin main --force)"
```

### Add Custom Semantic Guidelines
```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --guideline "Treat modifications to mock test fixtures as safe routine writes"
```

### Adjust Security Classifier Timeout
```bash
# Set 8-second timeout for complex monorepo classification
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --timeout 8.0
```
