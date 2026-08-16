---
okf_version: "0.2"
type: "guide"
title: "Using & Authoring Permission Bundles"
description: "How to discover, enable, disable, and author custom permission bundles with DAG inheritance."
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
  - "hooks/bundles/__init__.py"
  - "skills/auto-permissions-configure/scripts/configure_permissions.py"
stale_after: "2027-08-16"
tags:
  - "bundles"
  - "guide"
  - "acl"
  - "dag"
---

# Using & Authoring Permission Bundles

Permission Bundles bundle common tools into reusable ACL profiles.

---

## 1. Discovering & Listing Bundles

List all available built-in, global, and project bundles:

```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --list-bundles
```

Output:
```text
📦 Available Permission Bundles:
--------------------------------------------------------------------------------
• git-inspect [builtin] (active)
    Read-only git repository inspection (status, log, diff, branch, show...)
• gh-readonly [builtin] (active)
    Read-only GitHub CLI queries (pr, issue, run, release...)
• python-tooling [builtin] (active)
    Standard Python test, lint, and packaging tools (pytest, ruff, uv, poetry...)
• rust-tooling [builtin]
    Standard Cargo build, test, and lint commands (cargo test, check, clippy...)
• node-tooling [builtin]
    Common JavaScript/TypeScript testing and linting (npm/pnpm/yarn/bun, eslint...)
• container-inspect [builtin]
    Safe container status inspection (podman/docker ps, logs, images...)
• dev-docs-read [builtin]
    Whitelisted read access to official developer documentation sites
• mcp-nmem [builtin]
    Read-only search, lookup, and memory query tools for Nowledge Mem MCP
```

Inspect the exact rules inside a specific bundle:

```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --bundle-info python-tooling
```

---

## 2. Enabling and Disabling Bundles

```bash
# Enable in project scope (shared via git in .agents/auto-permissions/config.json)
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --enable-bundle git-inspect \
  --enable-bundle python-tooling

# Disable / mask a bundle in local or session scope
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project_local \
  --disable-bundle node-tooling
```

---

## 3. Authoring Custom Project Bundles

Create a new bundle file in `.agents/auto-permissions/bundles/my_team_ci.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "my-team-ci",
  "description": "Internal CI and build tooling for our microservices",
  "version": "1.0.0",
  "extends": ["git-inspect", "python-tooling"],
  "allow": [
    "command(./scripts/build_all.sh*)",
    "command(make test*)",
    "url(https://ci.internal.corp/*)"
  ],
  "ask": [
    "command(./scripts/deploy_staging.sh*)"
  ],
  "custom_guidelines": [
    "Treat ./scripts/build_all.sh as a safe routine build step."
  ]
}
```

Now enable `"my-team-ci"` in your repository `config.json`. It will automatically inherit all rules from `git-inspect` and `python-tooling` with zero duplicate configuration!
