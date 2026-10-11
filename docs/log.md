# History

## 2026-10-11
* **Creation**: Added docs/architecture/preset-and-sandbox-interplay.md documenting permission presets, sandboxing boundaries, bidirectional policy transformation, and the complete execution truth table across presets.
* **Update**: Conformed docs bundle to OKF v0.2 frontmatter schemas, sources syntax, and taxonomy.
* **Update**: Added GitHub Actions workflow (.github/workflows/pages.yml) using abn/okf-wiki/action@v1 for GitHub Pages publishing.
* **Update**: Aligned PreToolUse hook output with Antigravity v2.21+ permissions engine by emitting canonical permissionOverrides arrays and supporting deny_unless_prior_grant semantics.
* **Update**: Segregated sandbox privilege elevation in policy engine, requiring explicit unsandboxed rules for BypassSandbox: true commands.
* **Update**: Modernized command pattern matching with literal token prefixes, shell expansion safeguards, regex: prefix, and canonical slash MCP notation.

## 2026-08-18
* **Update**: Clarified classifier SYSTEM_INSTRUCTION rules to explicitly authorize non-destructive file reads when target paths are verbatim named in user prompts.
* **Update**: Added automated regression tests for explicit user path prompt directives.

## 2026-08-16
* **Creation**: Initial OKF v0.2 wiki structure and concept pages.
* **Creation**: Modularized architecture documentation covering the fast-path cascade, security model, OS sandboxing, KV-cache prefix optimization, and permission bundles.
* **Creation**: Ingested empirical benchmark studies for rule scaling latency, classifier schema impact, and KV-cache retention.
* **Creation**: Authored operational guides for CI/CD workflows, multi-agent governance, and troubleshooting.
* **Creation**: Documented interactive agent skills (configure, audit, fix, test).
* **Update**: Standardized default governance surfaces to subagents: true and schedule: true.
* **Creation**: Published reference specifications for policy schemas, the 8-bundle catalog, MCP tool governance, and lifecycle hooks.
