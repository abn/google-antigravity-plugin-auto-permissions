#!/usr/bin/env python3
"""
CLI Test Helper for Google Antigravity Auto-Permissions Plugin.
Evaluates a simulated user prompt and candidate tool action against static ACL policies
and the Gemini security classifier, displaying decision breakdowns and collapsible raw traces.
"""

import argparse
import json
import os
import sys
from typing import Any

# Ensure plugin root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
plugin_root = os.path.abspath(os.path.join(current_dir, "../../.."))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from hooks.classifier import classify_tool_call, format_classifier_payload  # noqa: E402
from hooks.policy_engine import evaluate_static_policies, load_custom_guidelines  # noqa: E402


def evaluate_simulated_permission(
    active_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    workspace_paths: list[str],
    prior_prompts: list[str] | None = None,
    tool_action: str | None = None,
    tool_summary: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Evaluates a simulated tool call against static policies and the security classifier."""
    prior_prompts = prior_prompts or []

    # 1. Fast-path static policy check
    static_verdict = evaluate_static_policies(
        tool_name=tool_name,
        tool_args=tool_args,
        session_dir=None,
        workspace_paths=workspace_paths,
    )

    custom_guidelines = load_custom_guidelines(workspace_paths=workspace_paths)

    if static_verdict:
        decision, reason, scope = static_verdict
        raw_prompt = format_classifier_payload(
            workspace_paths=workspace_paths,
            prior_prompts=prior_prompts,
            active_prompt=active_prompt,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_action=tool_action,
            tool_summary=tool_summary,
            custom_guidelines=custom_guidelines,
        )
        return {
            "mode": f"static_acl_{scope}",
            "decision": decision,
            "reason": reason,
            "risk_category": f"static_policy_{scope}",
            "confidence": 1.0,
            "latency_ms": 0.2,
            "raw_prompt": raw_prompt,
            "model_response": {
                "decision": decision,
                "reason": reason,
                "risk_category": f"static_policy_{scope}",
                "confidence": 1.0,
            },
            "error": None,
        }

    # 2. Invoke Gemini security classifier
    raw_prompt, classification, error, latency_ms = classify_tool_call(
        workspace_paths=workspace_paths,
        prior_prompts=prior_prompts,
        active_prompt=active_prompt,
        tool_name=tool_name,
        tool_args=tool_args,
        tool_action=tool_action,
        tool_summary=tool_summary,
        custom_guidelines=custom_guidelines,
        api_key=api_key,
    )

    return {
        "mode": "gemini_classifier",
        "decision": classification.get("decision", "ask"),
        "reason": classification.get("reason", "Automated classification."),
        "risk_category": classification.get("risk_category", "unknown"),
        "confidence": classification.get("confidence", 0.0),
        "latency_ms": latency_ms,
        "raw_prompt": raw_prompt,
        "model_response": classification,
        "error": error,
    }


def format_markdown_report(
    active_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    result: dict[str, Any],
) -> str:
    """Formats the evaluation result as a rich Markdown report with collapsible folds."""
    decision = result["decision"].upper()
    badge = (
        "🟢 **ALLOW**"
        if decision == "ALLOW"
        else ("🔴 **DENY**" if decision in ("DENY", "SOFT_DENY", "HARD_DENY") else "🟡 **ASK**")
    )
    mode_str = (
        f"Static ACL ({result['latency_ms']:.1f}ms)"
        if "static_acl" in result["mode"]
        else f"Gemini 2.5 Flash ({result['latency_ms']:.0f}ms)"
    )

    args_preview = (
        tool_args.get("CommandLine")
        or tool_args.get("TargetFile")
        or tool_args.get("AbsolutePath")
        or tool_args.get("Url")
        or json.dumps(tool_args)
    )

    md = f"""### 🛡️ Permission Test Verdict: {badge}

| Property | Value |
| :--- | :--- |
| **Tool Action** | `{tool_name}` |
| **Target / Command** | `{args_preview}` |
| **Evaluation Mode** | {mode_str} |
| **Risk Category** | `{result["risk_category"]}` |
| **Confidence** | `{result["confidence"]:.2f}` |
| **Verdict Reason** | {result["reason"]} |

<details>
<summary>🔍 <b>Classifier Prompt Payload (Input)</b></summary>

```xml
{result["raw_prompt"]}
```

</details>

<details>
<summary>🤖 <b>Model JSON Response (Output)</b></summary>

```json
{json.dumps(result["model_response"], indent=2)}
```

</details>
"""
    if result.get("error"):
        md += f"\n> [!WARNING]\n> Classifier Error encountered: {result['error']}\n"

    return md


def main():
    parser = argparse.ArgumentParser(
        description="Test how auto-permissions evaluates a candidate tool call against a prompt."
    )
    parser.add_argument("prompt", nargs="?", help="Active user prompt to test against.")
    parser.add_argument(
        "--command", "-c", help="Command line string for run_command (e.g. 'git push origin main')."
    )
    parser.add_argument(
        "--tool", "-t", default="run_command", help="Tool name (default: run_command)."
    )
    parser.add_argument(
        "--target",
        "-T",
        help="Target file path or URL for write_to_file, view_file, or read_url_content.",
    )
    parser.add_argument("--args", "-a", help="JSON dictionary string for tool arguments.")
    parser.add_argument(
        "--workspace",
        "-w",
        default=os.getcwd(),
        help="Workspace root path (default: current directory).",
    )
    parser.add_argument(
        "--history",
        "-H",
        action="append",
        default=[],
        help="Prior user prompt turn (can be repeated).",
    )
    parser.add_argument(
        "--markdown", "-m", action="store_true", help="Output as Markdown with collapsible folds."
    )
    parser.add_argument("--json", "-j", action="store_true", help="Output as raw JSON.")

    args = parser.parse_args()

    active_prompt = args.prompt or ""
    if not active_prompt and not sys.stdin.isatty():
        active_prompt = sys.stdin.read().strip()

    if not active_prompt:
        parser.error("An active user prompt is required (via positional argument or stdin).")

    tool_args: dict[str, Any] = {}
    if args.args:
        try:
            tool_args = json.loads(args.args)
        except json.JSONDecodeError as exc:
            parser.error(f"Invalid JSON passed to --args: {exc}")
    elif args.command:
        tool_args = {"CommandLine": args.command}
    elif args.target:
        if args.tool in ("write_to_file", "replace_file_content"):
            tool_args = {"TargetFile": args.target}
        elif args.tool in ("view_file",):
            tool_args = {"AbsolutePath": args.target}
        elif args.tool in ("read_url_content",):
            tool_args = {"Url": args.target}
        elif args.tool in ("list_dir",):
            tool_args = {"DirectoryPath": args.target}
        elif args.tool in ("grep_search",):
            tool_args = {"SearchPath": args.target}
        else:
            tool_args = {"Target": args.target}
    else:
        # Default fallback
        tool_args = {"CommandLine": "ls"}

    res = evaluate_simulated_permission(
        active_prompt=active_prompt,
        tool_name=args.tool,
        tool_args=tool_args,
        workspace_paths=[os.path.abspath(args.workspace)],
        prior_prompts=args.history,
    )

    if args.json:
        print(json.dumps(res, indent=2))
    elif args.markdown:
        print(format_markdown_report(active_prompt, args.tool, tool_args, res))
    else:
        print("=" * 80)
        print(f"AUTO-PERMISSIONS TEST VERDICT: {res['decision'].upper()}")
        print("=" * 80)
        print(f"Evaluation Mode : {res['mode']} ({res['latency_ms']:.1f}ms)")
        print(f"Risk Category   : {res['risk_category']}")
        print(f"Confidence      : {res['confidence']:.2f}")
        print(f"Reason          : {res['reason']}")
        print("-" * 80)
        print("Classifier Prompt Payload:")
        print(res["raw_prompt"])
        print("-" * 80)
        print("Model JSON Response:")
        print(json.dumps(res["model_response"], indent=2))
        print("=" * 80)


if __name__ == "__main__":
    main()
