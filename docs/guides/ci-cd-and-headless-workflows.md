---
okf_version: "0.2"
type: "guide"
title: "CI/CD & Headless Autonomous Workflows"
description: "Best practices for running headless non-interactive Antigravity agents in continuous integration pipelines without blocking on permission prompts."
category: "guides"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "operational-best-practices"
  verified:
    tier: "ci_pipeline_tests"
    date: "2026-08-16"
sources:
  - "hooks/policy_engine.py"
  - "hooks/bundles/__init__.py"
stale_after: "2027-08-16"
tags:
  - "guides"
  - "ci-cd"
  - "headless"
  - "automation"
  - "github-actions"
---

# CI/CD & Headless Autonomous Workflows

When deploying autonomous AI coding agents inside headless environments (GitHub Actions, GitLab CI, Jenkins, Argo Workflows), interactive terminal prompts (`stdin`) cause the workflow to hang or fail.

`auto-permissions` enables robust headless execution by combining **pre-seeded permission bundles** with **strict static ACL policies**.

---

## 1. Pre-Seeding Repository Bundles for CI

Commit a `.agents/auto-permissions/config.json` file to your repository that activates the relevant tooling bundles for your project:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "version": "1.0.0",
  "bundles": [
    "git-inspect",
    "python-tooling",
    "gh-readonly"
  ],
  "allow": [
    "command(./scripts/ci_test.sh*)",
    "command(coverage report*)"
  ],
  "trust_workspace_writes": true,
  "timeout": 8.0
}
```

---

## 2. GitHub Actions Workflow Example

```yaml
name: "Autonomous PR Reviewer & Linter"

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  agentic-review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - name: Install Auto-Permissions Plugin
        run: |
          mkdir -p ~/.gemini/config/plugins
          git clone https://github.com/abn/google-antigravity-plugin-auto-permissions.git \
            ~/.gemini/config/plugins/auto-permissions

      - name: Run Antigravity Agent in Headless Mode
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          agy run --non-interactive "Review PR changes, execute test suite with pytest, and verify linting with ruff."
```

---

## 3. Headless Failure Mode Prevention

1. **Deterministic Static Fast-Path:** All test execution (`pytest`), linting (`ruff`), and Git queries execute via static ACL ($<0.3\text{ ms}$), completely bypassing external LLM network latency in CI.
2. **Fail-Closed Gate:** If an agent attempts an unauthorized destructive operation or network exfiltration, the gate terminates with `hard_deny` rather than hanging on interactive prompt input.
