#!/usr/bin/env python3
"""
CLI helper to inspect and summarize auto-permissions audit records from audit.jsonl.
Supports plain terminal output and compact Markdown summary tables.
"""

import argparse
import json
import os
import sys

# Ensure plugin root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
plugin_root = os.path.abspath(os.path.join(current_dir, "../../.."))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from hooks.audit_logger import (  # noqa: E402
    generate_markdown_summary,
    load_audit_records,
)


def inspect_audit_log(audit_path: str, limit: int = 20, as_markdown: bool = False) -> None:
    records = load_audit_records(audit_path)
    if not records:
        print(f"No audit records found at: {audit_path}")
        return

    if as_markdown:
        print(generate_markdown_summary(records, limit=limit))
        return

    total = len(records)
    decisions = {}
    for r in records:
        d = r.get("hook_output", {}).get("decision", "unknown")
        decisions[d] = decisions.get(d, 0) + 1

    print("=" * 80)
    print(f"AUTO-PERMISSIONS AUDIT SUMMARY (Total Records: {total})")
    print("=" * 80)
    print("Decision Breakdown:")
    for d, count in decisions.items():
        pct = (count / total) * 100.0
        print(f"  - {d.upper():<10}: {count:>4} ({pct:>5.1f}%)")
    print("-" * 80)
    print(f"Recent {min(limit, total)} Classification Traces:")
    print("-" * 80)

    for idx, r in enumerate(records[-limit:], 1):
        ts = r.get("timestamp", "")
        tool = r.get("toolCall", {}).get("name", "")
        args = r.get("toolCall", {}).get("args", {})
        cmd = args.get("CommandLine") or args.get("TargetFile") or json.dumps(args)[:60]
        decision = r.get("hook_output", {}).get("decision", "").upper()
        reason = r.get("hook_output", {}).get("reason", "")
        latency = r.get("classification", {}).get("latency_ms", 0.0)

        print(f"[{idx}] {ts} | {decision:<6} | {latency:>6.1f}ms | Tool: {tool}")
        print(f"    Target: {cmd}")
        print(f"    Reason: {reason}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Inspect and summarize auto-permissions audit records."
    )
    parser.add_argument("audit_log", nargs="?", default="./audit.jsonl", help="Path to audit.jsonl")
    parser.add_argument("--limit", "-n", type=int, default=10, help="Number of traces to show.")
    parser.add_argument(
        "--markdown", "-m", action="store_true", help="Output as collapsible Markdown table."
    )

    args = parser.parse_args()
    inspect_audit_log(args.audit_log, limit=args.limit, as_markdown=args.markdown)


if __name__ == "__main__":
    main()
