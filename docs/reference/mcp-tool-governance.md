---
okf_version: "0.2"
type: "reference"
title: "Model Context Protocol (MCP) Tool Governance"
description: "Specification and rule patterns for governing Model Context Protocol (MCP) servers, tools, resources, and custom prefixes."
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
  - "hooks/bundles/mcp_nmem.json"
stale_after: "2027-08-16"
tags:
  - "reference"
  - "mcp"
  - "tools"
  - "governance"
---

# Model Context Protocol (MCP) Tool Governance

Antigravity seamlessly integrates with external MCP servers (e.g. `nowledge-mem`, `chrome-devtools`, `postgres`, `github-mcp`).

`auto-permissions` allows granular ACL control over MCP tools using the `mcp:<server>:<tool>` rule format.

---

## 1. Rule Syntax for MCP Tools

```text
mcp:<server_name>:<tool_name>
```

### Pattern Matching Examples

| Pattern | Scope | Behavior |
| :--- | :--- | :--- |
| `mcp:nowledge-mem:memory_search` | Exact Tool | Matches only the `memory_search` tool on `nowledge-mem`. |
| `mcp:nowledge-mem:*` | Wildcard Server | Auto-approves all tools on the `nowledge-mem` server. |
| `mcp:chrome-devtools:navigate_page` | Exact Tool | Matches page navigation on Chrome DevTools. |
| `mcp:postgres:read_*` | Prefix Wildcard | Matches all read-only database queries (e.g. `read_table`, `read_schema`). |

---

## 2. In-Tree MCP Invocations

Antigravity invokes MCP tools via two calling conventions:
1. **Direct Native Tool Calling:** e.g. `mcp_nowledge-mem_memory_search` or `mcp_chrome-devtools_navigate_page`.
2. **Lazy Tool Router:** `call_mcp_tool(ServerName="nowledge-mem", ToolName="memory_search", Arguments={...})`.

The policy engine automatically normalizes both calling styles into canonical `mcp:<server>:<tool>` representations during static policy evaluation.

---

## 3. Bundled MCP Catalog (`mcp-nmem`)

The built-in `mcp-nmem` bundle activates safe read-only queries for the Nowledge Mem personal knowledge graph:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "mcp-nmem",
  "description": "Read-only tools for Nowledge Mem personal knowledge graph",
  "allow": [
    "mcp:nowledge-mem:memory_search",
    "mcp:nowledge-mem:read_working_memory",
    "mcp:nowledge-mem:get_wiki_page",
    "mcp:nowledge-mem:query_sources",
    "mcp:nowledge-mem:query_library",
    "mcp:nowledge-mem:list_crystals",
    "mcp:nowledge-mem:graph_stats"
  ]
}
```
