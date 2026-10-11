# Architecture

Core technical architecture, lifecycle hooks, prefix caching invariants, and security boundary specifications.

- [Overview](overview.md) — Multi-tier cascade, sub-millisecond fast-path evaluation, and runtime lifecycle hooks.
- [Security Model](security-model.md) — Threat model, decoupled classifier payload, and injection defense.
- [Sandbox & OS Isolation](sandbox-and-os-isolation.md) — OS sandboxing (Landlock, Bubblewrap) vs. intent classification, and bypass elevation detection.
- [Permission Presets, Sandboxing, & Classifier Interplay](preset-and-sandbox-interplay.md) — Permission presets (`Default`, `Request Review`, `Turbo`), sandboxing boundaries, and classifier decision flow.
- [KV-Cache Optimization](kv-cache-optimization.md) — Prefix invariance, chronological layering, and prompt caching.
- [Same-Turn File Grants](same-turn-file-grants.md) — Intra-turn acceleration and immediate execution grants for newly authored files.
- [Permission Bundles](permission-bundles.md) — Bundle DAG inheritance (`extends`), scoping, and dual-resolution layout.
