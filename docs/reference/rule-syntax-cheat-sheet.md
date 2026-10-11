---
okf_version: '0.2'
type: reference
title: Static ACL Rule Syntax & Pattern Cheat Sheet
description: Complete regex, wildcard, glob, and prefix matching cheat sheet for static
  policy rules.
category: reference
status: stable
trust:
  generated:
    agent: antigravity
    method: code-analysis
  verified:
    tier: test_suite
    date: '2026-08-16'
sources:
- resource: hooks/policy_engine.py
stale_after: '2027-08-16'
tags:
- reference
- syntax
- rules
- regex
- patterns
---

# Static ACL Rule Syntax & Pattern Cheat Sheet

`auto-permissions` supports 5 standard resource matching syntax patterns for static policy rules.

---

## 1. Syntax Patterns

### A. Command Patterns (`command(...)`)
Matches shell command lines executed via `run_command` in the default sandboxed execution environment.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| `command(<binary>*)` | `command(pytest*)` | Literal token prefix matching. Matches `pytest`, `pytest -v`, `pytest tests/test_core.py`. |
| `command(<prefix> <subcmd>*)` | `command(git status*)` | Literal token prefix matching. Matches `git status`, `git status --short`. |
| `command(<exact>)` | `command(cargo test --lib)` | Exact match when no wildcard is provided. |
| `command(regex:<pattern>)` | `command(regex:npm run (build.*))` | Matches commands via anchored regular expression. |
| Global Wildcard | `command(*)` | Matches all commands. |
| Subshell Guard | `command(echo $(id))` | Shell expansion metacharacters (`$(...)`, backticks, `$((...))`, `<(...)`, `>(...)`, `{a,b}`) automatically disable prefix matching and require exact match. |

> [!NOTE]
> `command(...)` allow rules strictly apply to sandboxed executions. If a tool call requests host elevation (`BypassSandbox: true`), `command(...)` allow rules will **not** match, preventing unintentional privilege escalation.

---

### B. Unsandboxed Host Elevation Patterns (`unsandboxed(...)`)
Matches commands executed with `BypassSandbox: true` (host kernel isolation bypassed).

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| `unsandboxed(<prefix>*)` | `unsandboxed(git push*)` | Literal token prefix for unsandboxed commands. |
| `unsandboxed(<exact>)` | `unsandboxed(gh pr create)` | Exact match for unsandboxed commands. |
| `unsandboxed(regex:<pattern>)` | `unsandboxed(regex:^git push origin [a-z0-9_-]+$)` | Regular expression matching for unsandboxed commands. |

---

### C. File & Path Patterns (`write_file(...)`, `read_file(...)`, `path(...)`)
Matches filesystem file paths accessed by `view_file`, `write_to_file`, `replace_file_content`.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Canonical Write File | `write_file(src/**/*.py)` | Matches file write modifications under `src/`. |
| Canonical Read File | `read_file(/var/log/app.log)` | Matches file reads for the specified target. |
| Workspace Relative | `path(src/**/*.py)` | Matches all Python files under `src/`. |
| Glob Pattern | `path(docs/**/*.md)` | Matches all Markdown files in `docs/`. |
| Absolute Prefix | `path(/tmp/test_dir/*)` | Matches files under `/tmp/test_dir/`. |

---

### D. URL Patterns (`read_url(...)`, `url(...)`)
Matches HTTP/HTTPS URLs fetched via `read_url_content`.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Canonical Host Read | `read_url(docs.google.com)` | Matches URL fetches targeting domain `docs.google.com`. |
| Domain Wildcard | `url(https://*.readthedocs.io/*)` | Matches any subdomain on ReadTheDocs. |
| Subpath Prefix | `url(https://docs.python.org/3/*)` | Matches all Python 3 documentation paths. |
| Exact URL | `url(https://pkg.go.dev/std)` | Matches exact standard library package page. |

---

### E. MCP Tool Patterns (`mcp(...)`)
Matches Model Context Protocol tool invocations.

| Syntax Pattern | Example | Matching Behavior |
| :--- | :--- | :--- |
| Canonical Tool | `mcp(nowledge-mem/memory_search)` | Canonical slash notation: specific tool on server. |
| Canonical Server Wildcard | `mcp(nowledge-mem/*)` | Canonical slash notation: all tools on server. |
| Legacy Colon Tool | `mcp:nowledge-mem:memory_search` | Legacy colon notation: specific tool on server. |
| Legacy Server Wildcard | `mcp:nowledge-mem:*` | Legacy colon notation: all tools on server. |
| Tool Prefix Wildcard | `mcp(*:read_*)` or `mcp(*/read_*)` | Matches any tool starting with `read_`. |

---

### F. Bare Tool Name Patterns
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
