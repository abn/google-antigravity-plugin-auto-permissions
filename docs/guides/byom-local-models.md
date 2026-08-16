---
okf_version: "0.2"
type: "guide"
title: "Bring Your Own Model (BYOM) & Local Inference"
description: "Configuring custom model providers including OpenAI-compatible servers (vLLM, Ollama, SGLang, Lemonade), Anthropic Claude, and Google Gemini."
category: "guides"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "code-analysis"
  verified:
    tier: "test_suite"
    date: "2026-08-16"
sources:
  - "hooks/classifier.py"
  - "skills/auto-permissions-configure/scripts/configure_permissions.py"
stale_after: "2027-08-16"
tags:
  - "byom"
  - "local-models"
  - "ollama"
  - "vllm"
  - "openai"
  - "anthropic"
---

# Bring Your Own Model (BYOM) & Local Inference

`auto-permissions` supports full multi-provider model routing using zero external runtime dependencies.

---

## Supported Provider Protocols

| Provider Option | Protocol | Recommended Models | Authentication Header |
| :--- | :--- | :--- | :--- |
| **`google`** | Gemini REST API | `gemini-2.5-flash`, `gemini-2.5-pro` | `x-goog-api-key` |
| **`openai`** | OpenAI Chat Completions API | `gemma-2-9b-it`, `qwen-2.5-coder`, `gpt-4o-mini` | `Authorization: Bearer <key>` |
| **`anthropic`** | Anthropic Messages API | `claude-3-5-haiku`, `claude-3-7-sonnet` | `x-api-key`, `anthropic-version` |

---

## 1. Configuring Local Inference with Ollama / vLLM

For offline or air-gapped development, route classification to a local GPU:

```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project_local \
  --provider openai \
  --model gemma-2-9b-it \
  --endpoint http://localhost:8000/v1/chat/completions \
  --api-key-env-var LOCAL_INFERENCE_KEY
```

---

## 2. Configuring Anthropic Claude

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

python3 skills/auto-permissions-configure/scripts/configure_permissions.py \
  --scope project \
  --provider anthropic \
  --model claude-3-5-haiku-20241022
```

---

## 3. Testing Provider Connectivity

Verify that your configured endpoint is responsive and properly calibrated:

```bash
python3 skills/auto-permissions-configure/scripts/configure_permissions.py --probe
```
