---
okf_version: "0.2"
type: "guide"
title: "Getting Started with Auto-Permissions"
description: "Quickstart guide for installing, configuring, and verifying the auto-permissions security gate in Google Antigravity."
category: "guides"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "user-guide-synthesis"
  verified:
    tier: "test_suite"
    date: "2026-08-16"
sources:
  - "README.md"
  - "hooks.json"
stale_after: "2027-08-16"
tags:
  - "quickstart"
  - "guide"
  - "installation"
---

# Getting Started with Auto-Permissions

This guide covers installing the plugin, setting up credentials, and running your first auto-approved agent session.

---

## 1. Prerequisites & Installation

The `auto-permissions` plugin requires **Python 3.10+** (Python 3.14 recommended) and runs with **zero third-party runtime dependencies**.

```bash
# Clone the plugin into your Antigravity plugins directory
git clone https://github.com/abn/google-antigravity-plugin-auto-permissions.git \
  ~/.gemini/config/plugins/auto-permissions
```

Antigravity automatically discovers the plugin manifest (`plugin.json`) and lifecycle hooks (`hooks.json`).

---

## 2. Authentication & Zero-Configuration Mode

`auto-permissions` operates out-of-the-box with **zero manual configuration**:

- **Zero-Key Inbuilt Mode (Default):** A bundled plugin sidecar (`sidecars/auto-permissions-worker/`) is spawned by Antigravity with the Language Server connection environment injected, and classifies via the single-turn `GetModelResponse` Connect-RPC call — no external API key. PreToolUse hooks (which run without that environment) call the sidecar over loopback HTTP; in contexts where the LS environment is available (tool execution, sidecar), the classifier talks to the Language Server directly.
- **Google Cloud Code OAuth Mode:** Automatically uses `GOOGLE_OAUTH_TOKEN` or active `gcloud` credentials when available.
- **Direct API Key (Optional):** If you prefer using a dedicated Google AI Studio key:
  ```bash
  export GEMINI_API_KEY="your-gemini-api-key"
  ```
- **Local BYOM Inference (Optional):** Route requests to local Ollama, vLLM, or Lemonade instances; see [`guides/byom-local-models.md`](byom-local-models.md).

---

## 3. Verify Gate Hook Functionality

Test the `PreToolUse` gate entrypoint directly with mock stdin:

```bash
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"git status"}},"workspacePaths":["/home/project"],"stepIdx":0}' | python3 ~/.gemini/config/plugins/auto-permissions/hooks/auto_approve_gate.py
```

Expected output:
```json
{"decision": "allow", "reason": "Safe read-only command"}
```

---

## 4. Enabling Your First Permission Bundle

Activate standard development bundles for your repository:

```bash
python3 ~/.gemini/config/plugins/auto-permissions/skills/auto-permissions-configure/scripts/configure_permissions.py \
  --enable-bundle git-inspect \
  --enable-bundle python-tooling
```

Your repository is now configured to auto-approve routine git and Python tooling operations in $<0.3\text{ ms}$!
