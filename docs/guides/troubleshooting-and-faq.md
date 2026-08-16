---
okf_version: "0.2"
type: "guide"
title: "Troubleshooting & Frequently Asked Questions (FAQ)"
description: "Diagnostic procedures and solutions for classifier fallback timeouts, HTTP errors, soft denials, and rule configuration conflicts."
category: "guides"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "troubleshooting-synthesis"
  verified:
    tier: "test_suite"
    date: "2026-08-16"
sources:
  - "hooks/policy_engine.py"
  - "hooks/classifier.py"
  - "skills/auto-permissions-audit/scripts/view_audit.py"
stale_after: "2027-08-16"
tags:
  - "guides"
  - "troubleshooting"
  - "faq"
  - "diagnostics"
---

# Troubleshooting & Frequently Asked Questions (FAQ)

This guide provides diagnostic steps for resolving common security gate warnings, classification timeouts, and permission conflicts.

---

## 1. Common Diagnostics & Solutions

### A. Fallback Timeout (`Classifier fallback: Classifier request timed out (>6.0s)`)
* **Symptom:** Operations that normally auto-approve suddenly prompt the user with a fallback escalation.
* **Root Cause:** Network latency or complex multi-turn prompt contexts exceeding the default $6.0\text{s}$ timeout window.
* **Resolution:**
  1. Increase the timeout threshold in Project or Global scope:
     ```bash
     python3 skills/auto-permissions-configure/scripts/configure_permissions.py --scope project --timeout 8.0
     ```
  2. Alternatively, enable the relevant Permission Bundle (e.g. `python-tooling`, `git-inspect`) to evaluate the command on the sub-millisecond static fast-path ($0.2\text{ms}$), completely avoiding the network classifier.

### B. HTTP 401 / Missing API Key
* **Symptom:** `Classifier fallback: API returned status 401: Invalid API key`.
* **Resolution:** Ensure `GEMINI_API_KEY` (or provider-specific key) is exported in your environment:
  ```bash
  export GEMINI_API_KEY="your-api-key"
  ```
  Verify health via `configure_permissions.py --probe`.

### B2. Zero-key `antigravity` provider fails with `Client sent an HTTP request to an HTTPS server`
* **Symptom:** Every guarded tool falls back to `ask` with reason `... HTTP 400 Bad Request: Client sent an HTTP request to an HTTPS server`.
* **Root Cause:** The Antigravity Language Server loopback is HTTPS-only (self-signed), but the classifier defaulted the `ANTIGRAVITY_LS_ADDRESS` (injected as a bare `host:port`) to plain `http://`.
* **Resolution:** Use a current release where the loopback defaults to `https://` (with an unverified cert) and falls back to the alternate scheme on a transport-level failure. Verify the provider is reachable:
  ```bash
  configure_permissions.py --list-models --provider antigravity
  ```

### C. Scope Deviation (`soft_deny`) on Legitimate Developer Action
* **Symptom:** Gate returns `Security Gate (Scope Deviation): ...`.
* **Root Cause:** The classifier detected that the proposed command (e.g. `cargo build --release`) deviated from the user's immediate prompt phrasing (e.g. "check types").
* **Resolution:**
  1. Use `auto-permissions-fix` to add an explicit allow rule:
     ```bash
     python3 skills/auto-permissions-fix/scripts/fix_permissions.py --scope project --apply
     ```
  2. Or add a custom semantic guideline to `.agents/auto-permissions/config.json`:
     ```json
     {
       "custom_guidelines": [
         "Treat release builds as safe routine development operations"
       ]
     }
     ```

---

## 2. FAQ

**Q: Does auto-permissions slow down my agent?**  
**A:** No. For routine commands covered by built-in bundles or static rules, gate evaluation takes **$<0.3\text{ ms}$** ($3,000\times$ faster than human interaction).

**Q: How do I completely disable the plugin for a single session?**  
**A:** Set `"trust_workspace_writes": true` and activate all relevant bundles in your session override, or configure `allow: ["*"]` in `<session_dir>/auto-permissions/session_overrides.json`.
