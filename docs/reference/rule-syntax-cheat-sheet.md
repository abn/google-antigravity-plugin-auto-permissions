---
okf_version: "0.2"
type: "reference"
title: "Static ACL Rule Syntax & Pattern Cheat Sheet"
description: "Complete regex, wildcard, glob, and prefix matching cheat sheet for static policy rules."
category: "reference"
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
stale_after: "2027-08-16"
tags:
  - "reference"
  - "syntax"
  - "rules"
  - "regex"
  - "patterns"
---

# Static ACL Rule Syntax & Pattern Cheat Sheet

`auto-permissions` supports 5 standard resource matching syntax patterns for static policy rules.

---

## 1. Syntax Patterns

### A. Command Patterns (`command(...)`)
Matches shell command lines executed via `run_command`.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| `command(<binary>*)` | `command(pytest*)` | Matches `pytest`, `pytest -v`, `pytest tests/test_core.py`. |
| `command(<prefix> <subcmd>*)` | `command(git status*)` | Matches `git status`, `git status --short`. |
| `command(<exact>)` | `command(cargo test --lib)` | Matches only the exact command string. |
| Regex Wildcard | `command(npm (test\|run lint)*)` | Matches either `npm test` or `npm run lint`. |

---

### B. Path Patterns (`path(...)`)
Matches filesystem file paths accessed by `view_file`, `write_to_file`, `replace_file_content`.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Workspace Relative | `path(src/**/*.py)` | Matches all Python files under `src/`. |
| Glob Pattern | `path(docs/**/*.md)` | Matches all Markdown files in `docs/`. |
| Absolute Prefix | `path(/tmp/test_dir/*)` | Matches files under `/tmp/test_dir/`. |

---

### C. URL Patterns (`url(...)`)
Matches HTTP/HTTPS URLs fetched via `read_url_content`.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Domain Wildcard | `url(https://*.readthedocs.io/*)` | Matches any subdomain on ReadTheDocs. |
| Subpath Prefix | `url(https://docs.python.org/3/*)` | Matches all Python 3 documentation paths. |
| Exact URL | `url(https://pkg.go.dev/std)` | Matches exact standard library package page. |

---

### D. MCP Tool Patterns (`mcp:...`)
Matches Model Context Protocol tool invocations.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Exact Tool | `mcp:nowledge-mem:memory_search` | Matches specific tool. |
| Server Wildcard | `mcp:nowledge-mem:*` | Matches all tools provided by `nowledge-mem`. |
| Prefix Wildcard | `mcp:postgres:read_*` | Matches any tool starting with `read_`. |

---

### E. Bare Tool Name Patterns
Matches tool names directly.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Exact Tool | `list_dir` | Matches all `list_dir` tool calls. |
| Tool Wildcard | `grep_*` | Matches `grep_search`. |

---

## 2. Precedence Order

```text
Deny Rules > Ask Rules > Allow Rules
Session Scope > Project Local Scope > Project Scope > Global Scope > Bundled Rules
```
