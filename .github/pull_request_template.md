<!--
PR TITLE (required): becomes the squash-merge headline on main and the Release Please release-note entry.

  type(scope): <imperative verb> <concise change>
  - imperative mood (add, fix, allow, document, sync, implement)
  - scoped (classifier, policy, sidecar, skills, security, deps, ...)
  - <= 72 chars
  - types: feat, fix, docs, chore, build, refactor, test, ci

Examples:
  feat(classifier): add zero-key Antigravity classification via plugin sidecar
  fix(classifier): allow help/usage invocations explicitly
  docs(security): document classifier limitations and tradeoffs
-->

## Problem

What issue or gap does this change address? Keep it concrete and scoped to the reader.

## Solution

What changed and why. Describe the approach and the reasoning, not just the diff.

## Testing

How this was verified (tests, lint, manual/live checks). Include the command and result where relevant (e.g. `uv run pytest`, accuracy-battery result, live hook check).
