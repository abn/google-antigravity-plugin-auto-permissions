---
okf_version: "0.2"
type: "architecture"
title: "Auto-Permissions Core Architecture & Cascade Lifecycle"
description: "Detailed specification of the multi-tier authorization cascade, sub-millisecond fast-path evaluation, and runtime lifecycle hooks."
category: "architecture"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "code-analysis"
  verified:
    tier: "test_suite_and_empirical_benchmarks"
    date: "2026-08-16"
sources:
  - "hooks/auto_approve_gate.py"
  - "hooks/policy_engine.py"
  - "hooks/classifier.py"
stale_after: "2027-08-16"
tags:
  - "architecture"
  - "fast-path"
  - "lifecycle"
  - "cascade"
---

# Auto-Permissions Core Architecture & Cascade Lifecycle

The `auto-permissions` plugin introduces a dual-layer security authorization architecture designed to eliminate permission fatigue without compromising workspace safety.

```mermaid
flowchart TD
    A[Tool Call Invocations] --> B[Fast-Path Static Evaluation Engine]
    
    subgraph FastPath ["Fast-Path Static Cascade (~0.1ms)"]
        B --> C{Intra-Turn Cache?}
        C -- Hit --> Z1[Return Cached Verdict]
        C -- Miss --> D{Ungoverned Tool Surface?}
        D -- Yes --> Z2[Return Allow]
        D -- No --> E{Safe Read-Only Command / Artifact?}
        E -- Yes --> Z3[Return Allow]
        E -- No --> F{Workspace Write Fast-Path?}
        F -- Yes --> Z4[Return Allow]
        F -- No --> G{Explicit Static Scope Rules?}
        G -- Match --> Z5[Return Allow / Deny / Ask]
        G -- No Match --> H{Active Permission Bundles?}
        H -- Match --> Z6[Return Allow / Deny / Ask with Provenance]
    end
    
    H -- No Match --> I[LLM Security Classifier Fallback (~1.4s)]
    
    subgraph ClassifierPath ["LLM Classifier Fallback (~1.4s)"]
        I --> J[Parse Sanitized Prompt History]
        J --> K[Compile Layered XML Payload]
        K --> L[REST API Call: Gemini / OpenAI / Anthropic]
        L --> M[JSON Schema Verdict & Reason Extraction]
        M --> N[Intra-Turn Cache Update]
    end
    
    N --> O[Asynchronous Non-Blocking Audit Logger]
    Z1 --> O
    Z2 --> O
    Z3 --> O
    Z4 --> O
    Z5 --> O
    Z6 --> O
    O --> P[PreToolUse Exit Decision Output]
```

---

## The 6-Stage Fast-Path Cascade

Every tool call intercepted by the `PreToolUse` hook (`hooks/auto_approve_gate.py`) executes through an in-memory cascade that completes in **$<0.3\text{ ms}$**:

1. **Intra-Turn Cache (~0.05ms):** Exact repeat tool invocations within the same turn index immediately reuse the previous authorization verdict.
2. **Ungoverned Surface Fast-Path (~0.05ms):** Read-only inspection tools (`list_dir`, `view_file`, `grep_search`, `read_url_content`) operate unhindered unless explicitly governed.
3. **Safe Read & Skill Discovery (~0.1ms):** Whitelisted read commands (`cat`, `git status`, `head`) and skill definition reads (`~/.gemini/antigravity/builtin/skills`, `~/.agents/skills`) are auto-approved.
4. **Workspace Write Fast-Path (~0.1ms):** When `trust_workspace_writes: true`, modifications to files strictly within workspace boundaries are auto-approved, while sensitive paths (`.git/`, `.ssh/`, `.env`) are escalated.
5. **Static ACL Policy Hierarchy (~0.1ms):** Evaluates user-defined static rules across Session $\rightarrow$ Project Local $\rightarrow$ Project $\rightarrow$ Global with strict `Deny > Ask > Allow` priority.
6. **Compiled Permission Bundles (~0.2ms):** Evaluates compiled rules across all active bundles (e.g. `git-inspect`, `python-tooling`, `gh-readonly`) with provenance attribution (`bundle:<slug>`).

---

## Fail-Closed LLM Classifier Fallback

If a candidate tool call does not hit any fast-path stage, execution delegates to the decoupled LLM security classifier:
- **Zero Startup Dependencies:** Uses standard library `urllib.request` without external runtime packages.
- **Fail-Closed Safety:** Any network timeout ($>6.0\text{s}$), HTTP error, or missing API key defaults to `{"decision": "ask", "reason": "Classifier fallback: ..."}`.
- **Non-Blocking Audit:** All verdicts append atomic JSON Lines records to `<session_dir>/auto-permissions/audit.jsonl`.
