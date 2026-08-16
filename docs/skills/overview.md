---
okf_version: "0.2"
type: "reference"
title: "Antigravity Skills Overview & Discovery"
description: "Overview of bundled agent skills, skill whitelist permissions, and interactive workflows."
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
  - "skills/auto-permissions-configure/SKILL.md"
  - "skills/auto-permissions-audit/SKILL.md"
  - "skills/auto-permissions-fix/SKILL.md"
  - "skills/auto-permissions-test/SKILL.md"
stale_after: "2027-08-16"
tags:
  - "skills"
  - "antigravity"
  - "interactive"
---

# Antigravity Skills Overview & Discovery

The `auto-permissions` plugin includes 5 specialized agent skills providing automated configuration, log inspection, policy remediation, simulation testing, and accuracy benchmarking.

---

## Bundled Skills Catalog

| Skill Name | Trigger / Usage | Description |
| :--- | :--- | :--- |
| **[`auto-permissions-configure`](configure-skill.md)** | "Configure permissions", "Enable bundle" | Interactive policy, guideline, timeout, and provider configuration. |
| **[`auto-permissions-audit`](audit-skill.md)** | "View audit log", "Check denials" | Inspects audit trails, latency metrics, and failure diagnostics. |
| **[`auto-permissions-fix`](fix-skill.md)** | "Fix permission denials", "Allow blocked tools" | Automatically analyzes audit denials and synthesizes scoped ACL rules. |
| **[`auto-permissions-test`](test-skill.md)** | "Test permission for <command>" | Dry-run simulation tool evaluating candidate tool calls against prompt history. |
| **[`auto-permissions-benchmark`](benchmark-skill.md)** | "Benchmark classifier accuracy" | Runs a labeled accuracy battery against any provider/model and reports a score. |

---

## Safe Skill Whitelist Discovery

When agents read skill definitions via `view_file`, `policy_engine.is_safe_skill_read` auto-approves reads targeting:
- `~/.gemini/antigravity/builtin/skills/`
- `~/.gemini/config/skills/`
- `~/.gemini/config/plugins/*/skills/`
- `<workspace>/.agents/skills/`
- Custom paths configured in `allowed_skill_paths` or active bundles.
