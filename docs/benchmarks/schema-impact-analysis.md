---
okf_version: "0.2"
type: "benchmark"
title: "Classifier Output Schema & Explainability Impact"
description: "Empirical comparison of security classifier output schemas: outcome-only vs outcome+reason vs category vs Chain-of-Thought."
category: "benchmarks"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "live-api-benchmarking"
  verified:
    tier: "empirical_benchmarks"
    date: "2026-08-16"
sources:
  - "hooks/classifier.py"
  - "scratch/benchmark_schema_impact.py"
  - "scratch/schema_benchmark_results.json"
stale_after: "2027-08-16"
tags:
  - "benchmarks"
  - "classifier"
  - "tokens"
  - "latency"
  - "schema"
---

# Classifier Output Schema & Explainability Impact

This benchmark analyzes the trade-offs in output token length, total roundtrip latency, decision accuracy, and agent self-correction when modifying the classifier output schema.

---

## 1. Empirical Results Across 4 Variants

Live measurements over 10 security test vectors evaluated against Gemini 2.5 Flash:

| Variant / Output Schema | Median Completion Tokens | Median Latency (ms) | Mean Latency (ms) | p95 Latency (ms) | Accuracy Score |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Variant 1: Outcome Only**<br>`{"decision": "..."}` | **7.0 tokens** | **$1,221.6\text{ ms}$** | $1,359.7\text{ ms}$ | $3,556.3\text{ ms}$ | **$90.0\%$** *(misclassified destructive wipe as mild ask)* |
| **Variant 2: Outcome + Reason**<br>`{"decision": "...", "reason": "..."}` | **40.0 tokens** | **$1,320.3\text{ ms}$** *(+98.7ms)* | $1,596.4\text{ ms}$ | $3,621.2\text{ ms}$ | **$100.0\%$** |
| **Variant 3: Outcome + Reason + Category**<br>*(Status Quo)* | **57.0 tokens** | **$1,419.1\text{ ms}$** *(+197.5ms)* | $1,402.0\text{ ms}$ | **$2,050.8\text{ ms}$** | **$100.0\%$** |
| **Variant 4: Reason First (CoT) $\rightarrow$ Outcome**<br>`{"reason": "...", "decision": "..."}` | **56.0 tokens** | **$2,025.3\text{ ms}$** *(+606.2ms)* | $2,074.6\text{ ms}$ | $3,653.3\text{ ms}$ | **$100.0\%$** |

---

## 2. Key Insights

1. **Marginal Latency Cost for Full Explainability:** Moving from bare booleans to full reasons and categories adds only **$+197.5\text{ ms}$** ($\sim 16\%$), while eliminating blind rejections for autonomous agents.
2. **Decision Anchoring:** Requiring a `risk_category` anchors attention and prevents ambiguous classifications.
3. **Avoid Reason-First CoT:** Generating reasons before decisions adds $+606\text{ ms}$ of latency without improving verdict accuracy.
