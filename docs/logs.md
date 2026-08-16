---
okf_version: "0.2"
type: "log"
title: "Auto-Permissions Wiki Mutation & Provenance Log"
description: "Audit trail of knowledge base revisions, empirical re-measurements, and documentation lifecycle events."
category: "log"
status: "active"
trust:
  generated:
    agent: "antigravity"
    method: "wiki-provenance-tracking"
  verified:
    tier: "documentation_audit"
    date: "2026-08-16"
sources:
  - "docs/index.md"
  - "docs/architecture/"
  - "docs/benchmarks/"
  - "docs/guides/"
  - "docs/skills/"
  - "docs/reference/"
stale_after: "2027-08-16"
tags:
  - "wiki-log"
  - "provenance"
  - "knowledge-evolution"
---

# Knowledge Base Evolution & Provenance Log

This log tracks documentation additions, structural refactors, benchmark refreshes, and verification lifecycle events for the `auto-permissions` knowledge base.

---

### 2026-08-16: OKF v0.2 Wiki Prototype & Empirical Ingestion

- **Initial OKF 0.2 Structure:**
  - Created root catalog index ([`index.md`](index.md)) with Mermaid concept graphs and topic taxonomy.
  - Applied OKF 0.2 YAML frontmatter headers across all documents (`type`, `trust`, `sources`, `stale_after`, `tags`).
- **Architecture Modularization:**
  - Authored [`architecture/overview.md`](architecture/overview.md) detailing the 6-stage sub-millisecond fast-path cascade.
  - Authored [`architecture/security-model.md`](architecture/security-model.md) documenting decoupled prompt payloads and injection defense.
  - Authored [`architecture/sandbox-and-os-isolation.md`](architecture/sandbox-and-os-isolation.md) documenting defense-in-depth between intent classification and Linux Landlock / kernel sandboxing.
  - Authored [`architecture/kv-cache-optimization.md`](architecture/kv-cache-optimization.md) standardizing chronological turn layering and envelope stripping.
  - Authored [`architecture/same-turn-file-grants.md`](architecture/same-turn-file-grants.md) explaining intra-turn execution grants for newly authored files.
  - Authored [`architecture/permission-bundles.md`](architecture/permission-bundles.md) covering bundle DAG resolution and scoped directory encapsulation.
- **Empirical Benchmarks Ingestion:**
  - Published [`benchmarks/rule-scaling-latency.md`](benchmarks/rule-scaling-latency.md) with microsecond latency metrics across 10 to 5,000 rules.
  - Published [`benchmarks/schema-impact-analysis.md`](benchmarks/schema-impact-analysis.md) comparing outcome-only vs reason vs category schemas on live Gemini 2.5 Flash.
  - Published [`benchmarks/kv-cache-retention.md`](benchmarks/kv-cache-retention.md) with prefix caching retention numbers.
- **Operational Guides & Skill Reference:**
  - Created step-by-step guides for configuration, bundle authoring, audit inspection, and BYOM local inference.
  - Authored [`guides/ci-cd-and-headless-workflows.md`](guides/ci-cd-and-headless-workflows.md) for running autonomous non-interactive agents in continuous integration.
  - Authored [`guides/multi-agent-governance.md`](guides/multi-agent-governance.md) for subagent delegation and boundary confinement.
  - Authored [`guides/troubleshooting-and-faq.md`](guides/troubleshooting-and-faq.md) for diagnostics and failure recovery.
  - Documented interactive skills (`configure`, `audit`, `fix`, `test`).
- **Security Invariant Updates:**
  - Standardized default governance surfaces to **`subagents: true`** and **`schedule: true`**, catching rogue scope deviations and unauthorized background tasks at the creation boundary while supporting high-throughput opt-outs (`governed_surfaces.subagents = false`).
- **Reference Schemas:**
  - Published complete JSON configuration schema ([`reference/policy-schema.md`](reference/policy-schema.md)).
  - Published full 8-bundle catalog specification ([`reference/bundle-catalog.md`](reference/bundle-catalog.md)).
  - Published Model Context Protocol governance specification ([`reference/mcp-tool-governance.md`](reference/mcp-tool-governance.md)).
  - Published Static ACL rule syntax cheat sheet ([`reference/rule-syntax-cheat-sheet.md`](reference/rule-syntax-cheat-sheet.md)).
  - Documented `PreToolUse` and `PreInvocation` hook contracts ([`reference/lifecycle-hooks.md`](reference/lifecycle-hooks.md)).
- **Zero-Key Authentication & Persistent Sidecar Worker:**
  - Introduced bundled background sidecar daemon (`sidecars/worker.py`, `sidecars/sidecar.json`) bridging the security gate to the active Antigravity Language Server session with persistent KV-prefix cache warmth.
  - Implemented multi-tier zero-key fallback cascade in `hooks/classifier.py` (`_call_antigravity_sidecar_api` -> `_call_cloudcode_oauth_api` -> fail closed).
  - **Superseded (2026-08-16):** The sidecar worker was removed. Zero-key classification now calls the Language Server directly via single-turn `GetModelResponse` over the HTTPS Connect-RPC loopback (transport defaulted to `https://`), resolving the model from the live `GetUserStatus` roster for self-healing on model retirement.
  - **Revised (2026-08-16):** A thin plugin sidecar (`sidecars/auto-permissions-worker/`) was restored. PreToolUse hooks run without the LS connection environment, so the gate calls the sidecar over loopback HTTP; the sidecar (spawned by Antigravity with the env injected) calls the single-turn `GetModelResponse` directly. This is the cross-platform hook path; contexts that carry the env still classify directly.

