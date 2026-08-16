---
okf_version: "0.2"
type: "reference"
title: "Policy Configuration & Session Overrides JSON Schema"
description: "Complete formal schema specification for configuration files and runtime session overrides."
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
stale_after: "2027-08-16"
tags:
  - "reference"
  - "schema"
  - "json"
---

# Policy Configuration JSON Schema

Configuration files (`.agents/auto-permissions/config.json`, `config.local.json`, `~/.gemini/config/auto-permissions/config.json`, and `<session_dir>/auto-permissions/session_overrides.json`) adhere to the following schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AutoPermissionsConfig",
  "type": "object",
  "properties": {
    "version": { "type": "string" },
    "allow": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Static allow rules matching tool names, commands, paths, or URLs."
    },
    "ask": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Static escalation rules forcing human interactive confirmation."
    },
    "deny": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Static prohibition rules permanently blocking matching tool actions."
    },
    "bundles": {
      "oneOf": [
        { "type": "array", "items": { "type": "string" } },
        {
          "type": "object",
          "properties": {
            "enabled": { "type": "array", "items": { "type": "string" } },
            "disabled": { "type": "array", "items": { "type": "string" } }
          }
        }
      ],
      "description": "Active bundle names or enabled/disabled masking objects."
    },
    "custom_bundles": {
      "type": "object",
      "description": "Inline bundle definitions."
    },
    "custom_guidelines": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Semantic domain instructions injected into classifier prompts."
    },
    "allowed_skill_paths": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Whitelisted filesystem directories for agent skill definition discovery."
    },
    "governed_surfaces": {
      "type": "object",
      "properties": {
        "subagents": { "type": "boolean" },
        "schedule": { "type": "boolean" },
        "generate_image": { "type": "boolean" }
      }
    },
    "provider": { "type": "string", "enum": ["google", "antigravity", "cloudcode", "openai", "anthropic", "gemini", "claude"] },
    "model": { "type": "string" },
    "endpoint_url": { "type": "string" },
    "api_key_env_var": { "type": "string" },
    "timeout": { "type": "number", "minimum": 0.5, "default": 6.0 },
    "trust_workspace_writes": { "type": "boolean", "default": true },
    "show_turn_summary": { "type": "boolean", "default": true }
  }
}
```
