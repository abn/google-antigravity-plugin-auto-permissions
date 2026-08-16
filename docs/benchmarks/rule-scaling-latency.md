---
okf_version: "0.2"
type: "benchmark"
title: "Empirical Rule Scaling & Fast-Path Latency Analysis"
description: "Empirical benchmark measuring static policy evaluation latency (in microseconds) across 10 to 5,000 rules."
category: "benchmarks"
status: "stable"
trust:
  generated:
    agent: "antigravity"
    method: "microsecond-perf-benchmark"
  verified:
    tier: "empirical_benchmarks"
    date: "2026-08-16"
sources:
  - "hooks/policy_engine.py"
  - "scratch/benchmark_rules_latency.py"
stale_after: "2027-08-16"
tags:
  - "benchmarks"
  - "latency"
  - "scaling"
  - "performance"
---

# Empirical Rule Scaling & Fast-Path Latency Analysis

This document records empirical latency measurements of the `auto-permissions` static policy engine across increasing rule set sizes on x86_64 hardware.

---

## 1. Built-in Bundles Baseline (All 8 Bundles / 77 Rules)

When all 8 pre-packaged bundles are active in a workspace:

| Measurement | Median Latency | 95th Percentile (p95) | 99th Percentile (p99) |
| :--- | :---: | :---: | :---: |
| **Bundle Resolution & DAG Compilation** | **$280.9\,\mu\text{s}$** ($0.28\text{ ms}$) | $385.7\,\mu\text{s}$ | $412.0\,\mu\text{s}$ |
| **Fast-Path Hit (First Rule: `git status`)** | **$225.0\,\mu\text{s}$** ($0.23\text{ ms}$) | $463.9\,\mu\text{s}$ | $591.8\,\mu\text{s}$ |
| **Fast-Path Hit (Deep Rule: `poetry install`)** | **$260.5\,\mu\text{s}$** ($0.26\text{ ms}$) | $344.4\,\mu\text{s}$ | $488.7\,\mu\text{s}$ |
| **Full-Scan Miss (Evaluates all 77 rules before LLM)** | **$266.5\,\mu\text{s}$** ($0.27\text{ ms}$) | $320.3\,\mu\text{s}$ | $510.1\,\mu\text{s}$ |

---

## 2. Scaling Growth Profile Across Rule Counts

| Total Rules | Worst-Case Match (Hit Last Rule) | Full-Scan Miss (Worst-Case Fallthrough) |
| :---: | :---: | :---: |
| **10 rules** | $28.3\,\mu\text{s}$ ($0.03\text{ ms}$) | $48.5\,\mu\text{s}$ ($0.05\text{ ms}$) |
| **50 rules** | $72.0\,\mu\text{s}$ ($0.07\text{ ms}$) | $94.8\,\mu\text{s}$ ($0.09\text{ ms}$) |
| **200 rules** | $234.5\,\mu\text{s}$ ($0.23\text{ ms}$) | $264.9\,\mu\text{s}$ ($0.26\text{ ms}$) |
| **500 rules** | $770.6\,\mu\text{s}$ ($0.77\text{ ms}$) | $818.4\,\mu\text{s}$ ($0.82\text{ ms}$) |
| **1,000 rules** | $10.9\text{ ms}$ | $10.9\text{ ms}$ |
| **2,500 rules** | $27.1\text{ ms}$ | $27.3\text{ ms}$ |
| **5,000 rules** | $54.2\text{ ms}$ | $54.5\text{ ms}$ |

---

## 3. Conclusions

1. **Sub-Millisecond Envelope:** Standard developer configurations (10–200 rules) execute in **$<0.3\text{ ms}$**.
2. **Zero Fallthrough Penalty:** On unmatched commands, the full static scan adds $<0.3\text{ ms}$ of overhead before delegating to the remote classifier ($1,400\text{ ms}$).
