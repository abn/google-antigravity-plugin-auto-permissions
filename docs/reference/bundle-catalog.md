---
okf_version: "0.2"
type: "reference"
title: "Built-in Permission Bundles Catalog"
description: "Comprehensive catalog of all 8 pre-packaged zero-dependency built-in bundles, descriptions, and rule patterns."
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
  - "hooks/bundles/__init__.py"
  - "hooks/bundles/*.json"
stale_after: "2027-08-16"
tags:
  - "reference"
  - "bundles"
  - "catalog"
---

# Built-in Permission Bundles Catalog

The `auto-permissions` plugin includes 8 pre-packaged, zero-dependency built-in bundles located in `hooks/bundles/`:

---

### 1. `git-inspect`
Read-only repository inspection.
- **Allowed Rules:**
  - `command(git status*)`
  - `command(git log*)`
  - `command(git diff*)`
  - `command(git branch*)`
  - `command(git show*)`
  - `command(git tag*)`
  - `command(git remote*)`
  - `command(git rev-parse*)`
  - `command(git describe*)`

---

### 2. `gh-readonly`
Read-only GitHub CLI queries.
- **Allowed Rules:**
  - `command(gh pr view*)`
  - `command(gh pr list*)`
  - `command(gh pr checks*)`
  - `command(gh pr diff*)`
  - `command(gh pr status*)`
  - `command(gh run list*)`
  - `command(gh run view*)`
  - `command(gh issue list*)`
  - `command(gh issue view*)`
  - `command(gh release list*)`
  - `command(gh release view*)`
  - `command(gh repo view*)`

---

### 3. `python-tooling`
Standard Python testing, formatting, linting, and packaging.
- **Allowed Rules:**
  - `command(pytest*)`
  - `command(python -m pytest*)`
  - `command(python3 -m pytest*)`
  - `command(uv run pytest*)`
  - `command(uv run --frozen pytest*)`
  - `command(ruff check*)`
  - `command(ruff format*)`
  - `command(black*)`
  - `command(flake8*)`
  - `command(mypy*)`
  - `command(uv lock*)`
  - `command(uv sync*)`
  - `command(poetry run *)`
  - `command(poetry check*)`
  - `command(poetry lock*)`
  - `command(poetry show*)`
  - `command(poetry install*)`

---

### 4. `rust-tooling`
Cargo build, check, test, clippy, and documentation.
- **Allowed Rules:**
  - `command(cargo test*)`
  - `command(cargo check*)`
  - `command(cargo clippy*)`
  - `command(cargo fmt*)`
  - `command(cargo doc*)`
  - `command(cargo build*)`

---

### 5. `node-tooling`
Node.js, npm, pnpm, yarn, and bun testing and formatting.
- **Allowed Rules:**
  - `command(npm test*)`
  - `command(npm run test*)`
  - `command(npm run lint*)`
  - `command(pnpm test*)`
  - `command(yarn test*)`
  - `command(bun test*)`
  - `command(npx eslint*)`
  - `command(npx prettier*)`
  - `command(eslint*)`
  - `command(prettier*)`

---

### 6. `container-inspect`
Docker and Podman status queries.
- **Allowed Rules:**
  - `command(docker ps*)`
  - `command(docker logs*)`
  - `command(docker images*)`
  - `command(docker inspect*)`
  - `command(podman ps*)`
  - `command(podman logs*)`
  - `command(podman images*)`
  - `command(podman inspect*)`

---

### 7. `dev-docs-read`
Whitelisted read access to official developer documentation sites.
- **Allowed Rules:**
  - `url(https://docs.python.org/*)`
  - `url(https://developer.mozilla.org/*)`
  - `url(https://*.readthedocs.io/*)`
  - `url(https://pkg.go.dev/*)`
  - `url(https://crates.io/*)`
  - `url(https://docs.rs/*)`
  - `url(https://www.npmjs.com/*)`

---

### 8. `mcp-nmem`
Read-only search, lookup, and memory query tools for Nowledge Mem MCP.
- **Allowed Rules:**
  - `mcp:nowledge-mem:memory_search`
  - `mcp:nowledge-mem:read_working_memory`
  - `mcp:nowledge-mem:get_wiki_page`
  - `mcp:nowledge-mem:query_sources`
  - `mcp:nowledge-mem:query_library`
  - `mcp:nowledge-mem:list_crystals`
  - `mcp:nowledge-mem:graph_stats`
