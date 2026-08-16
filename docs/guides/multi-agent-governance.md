---
okf_version: "0.2"
type: "guide"
title: "Multi-Agent Permission Governance & Subagent Scoping"
description: "How auto-permissions handles subagent delegation, governed surfaces toggles, and workspace boundary confinement across multi-agent workflows."
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
  - "rules/auto_permissions.md"
stale_after: "2027-08-16"
tags:
  - "guides"
  - "multi-agent"
  - "subagents"
  - "governance"
---

# Multi-Agent Permission Governance & Subagent Scoping

Modern agentic coding workflows often spawn specialized subagents (e.g. `researcher`, `technical_writer`, `tester`) via `invoke_subagent` and `define_subagent`.

`auto-permissions` provides a dual-model governance architecture for multi-agent workflows:

```mermaid
graph TD
    ParentAgent[Parent Agent] --> SubagentCall{invoke_subagent / define_subagent}
    SubagentCall --> SurfaceCheck{governed_surfaces.subagents?}
    SurfaceCheck -- false (Default Fast-Path) --> FastAllow[🟢 ALLOW (~0.05ms)<br/>Subagent spawns freely]
    SurfaceCheck -- true (Opt-In Security Gate) --> Classify[LLM Security Classifier / Static ACL]
    Classify -- In Scope --> SubagentSpawn[Spawn Subagent Process]
    Classify -- Prohibited / Escalated --> Block[🔴 DENY / 🟡 ASK]

    SubagentSpawn --> SubagentExecution[Subagent Executes Tool Calls]
    SubagentExecution --> SubagentGate[PreToolUse Gate for Subagent Actions]
    SubagentGate --> WorkspaceContainment{Confined to Workspace Roots?}
    WorkspaceContainment -- Yes --> StaticCascade[Evaluate Static ACL & Bundles]
    WorkspaceContainment -- No --> HardBlock[🔴 HARD_DENY: Boundary Escape]
```

---

## 1. Governed by Default vs. High-Throughput Opt-Out

By default, subagent creation (`invoke_subagent`, `define_subagent`) is **strictly governed**. The security classifier inspects the candidate subagent's role and prompt to ensure they align with the active user intent, catching rogue scope deviations before background execution begins.

### Opting Out for High-Throughput Pipelines
If you are running automated, high-throughput multi-agent orchestration harnesses where subagent spawning must execute on the sub-millisecond fast-path (~0.05ms):

```bash
# Explicitly opt out of governing subagent creation
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --govern-surface subagents=false
```

Configuration in `.agents/auto-permissions/config.json`:
```json
{
  "governed_surfaces": {
    "subagents": false,
    "schedule": true,
    "generate_image": false
  }
}
```

---

## 2. Invariant: Child Subagents Inherit Full Gate Protection

When a subagent executes tool calls (`run_command`, `write_to_file`, `mcp_*`):
- Every tool action initiated by the subagent is intercepted by the `PreToolUse` hook.
- Subagents are strictly confined to the parent workspace roots and inherited project ACL policies.
- A subagent cannot elevate permissions or bypass the security gate.
