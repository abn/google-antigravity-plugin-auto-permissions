---
name: auto-permissions-benchmark
description: >-
  Run a labeled accuracy benchmark battery against the configured auto-permissions security classifier (any provider/model), reporting per-case verdicts and an accuracy score to validate a model choice before adopting it.
---

# Auto-Permissions Benchmark Skill

Use this skill when the user asks to measure or validate the accuracy of a classifier provider/model (e.g. before switching the classification model), or to compare two models on the same battery.

The benchmark runs a fixed set of labeled `(prompt, tool, arguments)` cases — covering safe routines, workspace writes/reads, external actions, destructive operations, and credential exfiltration — and reports whether each verdict lands in the accepted set plus an overall accuracy score.

---

## Usage Recipes

### 1. Benchmark the Default (Zero-Key Antigravity) Model

```bash
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py --provider antigravity
```

### 2. Benchmark a Specific Antigravity Roster Model

```bash
# By friendly label or opaque token
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider antigravity --model "Gemini 3.7 Flash (High)"
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider antigravity --model MODEL_GOOGLE_GEMINI_2_5_FLASH
```

### 3. Benchmark Any Provider / Model

```bash
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider openai --model gpt-4o-mini --endpoint-url "http://localhost:8000/v1/chat/completions"

python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider google --model gemini-2.5-flash
```

### 4. Machine-Readable Output

```bash
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider antigravity --model "Gemini 3.5 Flash (Low)" --json
```

---

## Interpreting Results

* A verdict is counted as passed when it lands in the case's `accepted` set. Most cases accept exactly one verdict; credential-access cases accept `ask` **or** `hard_deny`, since both are fail-safe for a security gate.
* **Accuracy** is `passed / total`. A single unexpected `allow` on a destructive/exfiltration case is a serious miss; a `hard_deny` where `ask` was expected is a conservative (safe) miss.
* Latency per case is printed to compare speed alongside accuracy (e.g. a faster low-effort model at equal accuracy is a good trade).

## Tuning Generation Parameters

The classifier's OpenAI-wire path defaults to deterministic, latency-bounded generation: `temperature 0.0`, `top_p 1.0`, `max_tokens 800`. Benchmark a candidate configuration by exporting the same `AUTO_PERMISSIONS_*` env vars the hook will honor:

```bash
AUTO_PERMISSIONS_TEMPERATURE=0.2 \
AUTO_PERMISSIONS_TOP_K=40 \
AUTO_PERMISSIONS_MAX_TOKENS=300 \
AUTO_PERMISSIONS_REASONING_EFFORT=low \
python3 skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py \
  --provider openai --model "Gemma-4-26B-A4B-NoThinking-qat-MTP" \
  --endpoint-url "http://127.0.0.1:13305/v1/chat/completions" \
  --api-key-env LEMONADE_API_KEY
```

Only values that pass the benchmark unchanged are safe to ship as defaults for that model/backend.

