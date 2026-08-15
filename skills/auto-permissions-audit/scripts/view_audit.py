#!/usr/bin/env python3
"""
CLI helper to inspect and summarize auto-permissions audit records from audit.jsonl.
Supports plain terminal output, compact Markdown summary tables, issue diagnostics,
and container sandbox elevation detection.
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
    diagnose_audit_records,
    generate_markdown_summary,
    load_audit_records,
)


def inspect_audit_log(
    audit_path: str,
    limit: int = 20,
    as_markdown: bool = False,
    diagnose: bool = False,
) -> None:
    if not os.path.exists(audit_path):
        print(
            f"No audit records found at: {audit_path}\n"
            "Note: The security gate has not evaluated any tool actions in this session yet."
        )
        return

    records = load_audit_records(audit_path)
    if not records:
        print(
            f"Audit log is empty at: {audit_path}\n"
            "Note: No tool actions recorded yet for this session."
        )
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

    # Diagnostic section
    diagnostics = diagnose_audit_records(records)
    has_issues = (
        diagnostics["denials"] or diagnostics["error_fallbacks"] or diagnostics["sandbox_bypasses"]
    )

    if diagnose or has_issues:
        print("=" * 80)
        print("🔍 SECURITY GATE ISSUE DIAGNOSTICS & RECOMMENDATIONS")
        print("=" * 80)

        if diagnostics["denials"]:
            print(f"🚨 Denials Detected ({len(diagnostics['denials'])}):")
            for den in diagnostics["denials"]:
                print(f"  - [{den['tool']}] {den['target']}")
                print(f"    Reason: {den['reason']}")
            print()

        if diagnostics["sandbox_bypasses"]:
            print(
                f"📦 Host Sandbox Elevation Events ({len(diagnostics['sandbox_bypasses'])}):\n"
                "  These commands were ALLOWED by auto-permissions but used BypassSandbox: true.\n"
                "  (Antigravity Container Sandbox mounted .git/ or target paths as read-only,\n"
                "  causing the host platform to display an interactive confirmation dialog.)"
            )
            for sb in diagnostics["sandbox_bypasses"]:
                print(f"  - [{sb['tool']}] {sb['target']}")
            print()

        if diagnostics["error_fallbacks"]:
            print(f"⚠️  Fallback Errors ({len(diagnostics['error_fallbacks'])}):")
            for err in diagnostics["error_fallbacks"]:
                print(f"  - {err['reason']}")
            print()

        if diagnostics["recommendations"]:
            print("💡 Actionable Recommendations & Mitigations:")
            for rec in diagnostics["recommendations"]:
                print(f"  * {rec}")
            print()


def find_default_audit_log(provided_path: str | None = None) -> str:
    """
    Resolves default audit log path, checking provided path,
    auto-permissions/ subdir, or legacy root.
    """
    if provided_path and os.path.exists(provided_path):
        return provided_path
    if os.path.isfile("./auto-permissions/audit.jsonl"):
        return os.path.abspath("./auto-permissions/audit.jsonl")
    if os.path.isfile("./audit.jsonl"):
        return os.path.abspath("./audit.jsonl")
    brain_dir = os.path.expanduser("~/.gemini/antigravity/brain")
    if os.path.isdir(brain_dir):
        candidates = []
        for root, _dirs, files in os.walk(brain_dir):
            if "audit.jsonl" in files:
                fpath = os.path.join(root, "audit.jsonl")
                candidates.append((os.path.getmtime(fpath), fpath))
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
    return provided_path or "./auto-permissions/audit.jsonl"


def main():
    parser = argparse.ArgumentParser(
        description="Inspect and summarize auto-permissions audit records."
    )
    parser.add_argument("audit_log", nargs="?", default=None, help="Path to audit.jsonl")
    parser.add_argument("--limit", "-n", type=int, default=10, help="Number of traces to show.")
    parser.add_argument(
        "--markdown", "-m", action="store_true", help="Output as collapsible Markdown table."
    )
    parser.add_argument(
        "--diagnose",
        "-d",
        action="store_true",
        help="Display automated issue diagnosis, sandbox bypass events, and recommendations.",
    )

    args = parser.parse_args()
    log_path = find_default_audit_log(args.audit_log)
    inspect_audit_log(
        log_path,
        limit=args.limit,
        as_markdown=args.markdown,
        diagnose=args.diagnose,
    )


if __name__ == "__main__":
    main()
