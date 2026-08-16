---
okf_version: "0.2"
type: "guide"
title: "Auto-Permissions Configure Skill Guide"
description: "Instructions and recipes for using the interactive configuration skill across Session, Project, and Global scopes."
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
stale_after: "2027-08-16"
tags:
  - "skills"
  - "configure"
  - "recipes"
---

# Auto-Permissions Configure Skill Guide

The `auto-permissions-configure` skill guides users through inspecting and mutating authorization settings.

---

## Interactive Capabilities

When activated, the agent guides the user through:
1. **Inspecting Configuration:** Renders effective policy tables across all 5 scopes.
2. **Bundle Management:** Enables/disables built-in and custom bundles.
3. **Static Rule Authoring:** Adds or removes `allow`, `ask`, and `deny` rules.
4. **Semantic Guidelines:** Appends domain-specific instructions to prompt headers.
5. **Provider Routing:** Configures custom endpoints (Gemini, OpenAI, Claude, Antigravity, Cloud Code) and lists available models.
6. **Layout Migration:** Migrates legacy flat files to the scoped layout.

---

## Direct CLI Recipes

```bash
# Enable bundle in project
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project --enable-bundle gh-readonly

# Add static rule
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project --allow "command(cargo check*)"

# Configure zero-key inbuilt Antigravity session
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project --provider antigravity

# List models the active Antigravity account serves (live roster with quota)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --list-models --provider antigravity

# Configure model endpoint
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project_local --provider anthropic --model claude-3-5-haiku-20241022
```
