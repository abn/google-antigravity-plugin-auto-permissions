---
okf_version: "0.2"
type: "reference"
title: "Lifecycle Hook Specifications & JSON Contracts"
description: "Input and output JSON contracts for PreToolUse (auto_approve_gate.py) and PreInvocation (pre_invocation.py)."
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
  - "hooks.json"
  - "hooks/auto_approve_gate.py"
  - "hooks/pre_invocation.py"
stale_after: "2027-08-16"
tags:
  - "reference"
  - "hooks"
  - "pre-tool-use"
  - "pre-invocation"
---

# Lifecycle Hook Specifications & JSON Contracts

Google Antigravity invokes plugin hooks via standard POSIX stdin/stdout JSON streams.

---

## 1. `PreToolUse` Hook (`hooks/auto_approve_gate.py`)

Invoked before any candidate tool call is executed.

### Input JSON Contract (stdin)
```json
{
  "toolCall": {
    "name": "run_command",
    "args": {
      "CommandLine": "pytest -v"
    }
  },
  "workspacePaths": ["/home/project"],
  "stepIdx": 4,
  "sessionDirectory": "/home/user/.gemini/antigravity/brain/<session_id>"
}
```

### Output JSON Contract (stdout)
```json
{
  "decision": "allow",
  "reason": "Safe read-only command"
}
```
*Valid decisions:* `"allow"`, `"ask"`, `"soft_deny"`, `"hard_deny"`.

---

## 2. `PreInvocation` Hook (`hooks/pre_invocation.py`)

Invoked at the beginning of an agent turn to inject transient disclosures or reminders into the trajectory.

### Output JSON Contract (stdout)
```json
{
  "injectSteps": [
    {
      "type": "USER_INPUT",
      "content": "🛡️ Auto-Permissions Security Disclosure (Turn 2): 4 actions allowed."
    }
  ]
}
```
