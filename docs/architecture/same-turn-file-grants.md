---
okf_version: "0.2"
type: "architecture"
title: "Same-Turn File Grants & Scratch Acceleration"
description: "How the static policy engine tracks newly written files in the active turn and grants immediate execution without classifier roundtrips."
category: "architecture"
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
  - "hooks/auto_approve_gate.py"
stale_after: "2027-08-16"
tags:
  - "architecture"
  - "fast-path"
  - "same-turn-grants"
  - "scratch"
---

# Same-Turn File Grants & Scratch Acceleration

When an AI agent works on a complex coding task, it frequently authors temporary test scripts, mock runners, or reproduction harnesses in workspace scratch directories (e.g. `scratch/test_repro.py`, `tests/test_new_feature.py`), and immediately invokes them with `python3` or `pytest`.

Without same-turn awareness, every newly created file invocation would require a separate 1.4s remote classifier roundtrip.

---

## 1. Mechanism & Lifecycle

`hooks/policy_engine.py` implements the `check_same_turn_file_grant` helper:

```mermaid
sequenceDiagram
    autonumber
    actor Agent
    participant Gate as PreToolUse Gate
    participant Session as Session Turn State
    participant Runner as Execution Harness

    Agent->>Gate: write_to_file("scratch/reproduce_bug.py")
    Gate->>Gate: Verify Workspace Write Fast-Path (0.1ms)
    Gate->>Session: Record "scratch/reproduce_bug.py" in Same-Turn Write Registry
    Gate-->>Agent: 🟢 ALLOW
    Agent->>Runner: Write file to disk

    Agent->>Gate: run_command("python3 scratch/reproduce_bug.py")
    Gate->>Session: check_same_turn_file_grant("scratch/reproduce_bug.py")
    Session-->>Gate: Verified (Written by agent in Step 1)
    Gate-->>Agent: 🟢 ALLOW (Fast-Path ~0.1ms)
    Agent->>Runner: Execute script
```

---

## 2. Security Boundaries & Invariants

1. **Turn-Scoped Ephemerality:** Same-turn file grants expire immediately when the active turn concludes (`stepIdx` reset or turn boundary).
2. **Workspace Path Containment:** Same-turn grants are strictly restricted to non-sensitive paths located within workspace roots.
3. **Sensitive Path Exclusion:** Writes to sensitive paths (`.git/`, `.ssh/`, `.env`, `.agents/auto-permissions/`) are permanently excluded from same-turn execution grants and require explicit classification or confirmation.
