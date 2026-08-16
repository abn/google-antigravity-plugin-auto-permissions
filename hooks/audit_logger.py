#!/usr/bin/env python3
"""
Rotatable Asynchronous Audit Logger for Google Antigravity Auto-Permissions Hook.
Appends atomic JSON Lines records to <session_dir>/audit.jsonl and manages log rotation.
Also provides audit diagnostics and summary formatters.
"""

import datetime
import json
import os
import threading
from typing import Any

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_BACKUP_COUNT = 3
DEFAULT_LOG_SUBDIR = "auto-permissions"
DEFAULT_LOG_NAME = "audit.jsonl"


def resolve_session_log_path(
    artifact_dir: str | None = None,
    transcript_path: str | None = None,
    conversation_id: str | None = None,
) -> str:
    """
    Resolves the active conversation's audit log file path in the auto-permissions/ subdirectory.
    Falls back to legacy root file if already present.
    """
    session_root = None
    if artifact_dir and os.path.isabs(artifact_dir):
        session_root = artifact_dir
    elif transcript_path and os.path.isfile(transcript_path):
        session_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(transcript_path)))
        )
    elif conversation_id:
        session_root = os.path.expanduser(f"~/.gemini/antigravity/brain/{conversation_id}")

    if session_root:
        scoped = os.path.join(session_root, DEFAULT_LOG_SUBDIR, DEFAULT_LOG_NAME)
        legacy = os.path.join(session_root, DEFAULT_LOG_NAME)
        if os.path.isfile(legacy) and not os.path.isfile(scoped):
            return legacy
        return scoped

    # Local fallback for standalone testing
    scoped_local = os.path.abspath(os.path.join(DEFAULT_LOG_SUBDIR, DEFAULT_LOG_NAME))
    legacy_local = os.path.abspath(DEFAULT_LOG_NAME)
    if os.path.isfile(legacy_local) and not os.path.isfile(scoped_local):
        return legacy_local
    return scoped_local


def resolve_session_root_dir(
    artifact_dir: str | None = None,
    transcript_path: str | None = None,
    conversation_id: str | None = None,
    log_path: str | None = None,
) -> str | None:
    """
    Resolves the canonical root directory of the active session
    (<session_dir> or ~/.gemini/antigravity/brain/<conversation_id>/).
    Unwraps any .system_generated/logs or auto-permissions/ subdirectories.
    """
    if artifact_dir and os.path.isabs(artifact_dir):
        return os.path.abspath(artifact_dir)
    if transcript_path and os.path.isabs(transcript_path):
        # <session_root>/.system_generated/logs/transcript.jsonl
        norm = os.path.abspath(transcript_path)
        return os.path.dirname(os.path.dirname(os.path.dirname(norm)))
    if conversation_id:
        return os.path.abspath(os.path.expanduser(f"~/.gemini/antigravity/brain/{conversation_id}"))
    if log_path and os.path.isabs(log_path):
        norm = os.path.abspath(log_path)
        d = os.path.dirname(norm)
        if os.path.basename(d) == "auto-permissions":
            return os.path.dirname(d)
        return d
    return None


def rotate_log_file_if_needed(
    log_path: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Rotates the log file if its size exceeds max_bytes."""
    if not os.path.exists(log_path):
        return

    try:
        if os.path.getsize(log_path) < max_bytes:
            return

        for i in range(backup_count - 1, 0, -1):
            sfn = f"{log_path}.{i}"
            dfn = f"{log_path}.{i + 1}"
            if os.path.exists(sfn):
                if os.path.exists(dfn):
                    os.remove(dfn)
                os.rename(sfn, dfn)

        dfn = f"{log_path}.1"
        if os.path.exists(dfn):
            os.remove(dfn)
        os.rename(log_path, dfn)
    except Exception:
        # Rotation failure should never crash the permission gate
        pass


def write_audit_record_sync(
    log_path: str,
    record: dict[str, Any],
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Synchronously writes an audit record with rotation checks."""
    try:
        parent_dir = os.path.dirname(os.path.abspath(log_path))
        os.makedirs(parent_dir, exist_ok=True)

        rotate_log_file_if_needed(log_path, max_bytes, backup_count)

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
    except Exception:
        # Audit logging failure should never crash the permission gate
        pass


def log_audit_event_async(
    artifact_dir: str | None,
    transcript_path: str | None,
    conversation_id: str | None,
    step_idx: int | None,
    tool_call: dict[str, Any],
    context: dict[str, Any],
    raw_prompt: str,
    classification: dict[str, Any],
    hook_output: dict[str, Any],
    latency_ms: float,
) -> threading.Thread:
    """Spawns an asynchronous worker to write the audit record without blocking the main gate."""
    log_path = resolve_session_log_path(artifact_dir, transcript_path, conversation_id)

    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "conversationId": conversation_id,
        "stepIdx": step_idx,
        "toolCall": tool_call,
        "context": context,
        "raw_prompt": raw_prompt,
        "classification": {**classification, "latency_ms": round(latency_ms, 2)},
        "hook_output": hook_output,
    }

    t = threading.Thread(target=write_audit_record_sync, args=(log_path, record), daemon=True)
    t.start()
    return t


def load_audit_records(audit_path: str) -> list[dict[str, Any]]:
    """Reads and parses JSON Lines audit records from file."""
    if not audit_path or not os.path.isfile(audit_path):
        return []

    records = []
    with open(audit_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def diagnose_audit_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyzes audit records to identify issues, anomalies, sandbox bypass events,
    and optimization opportunities. Returns structured findings and actionable recommendations.
    """
    total = len(records)
    denials = []
    high_latency = []
    error_fallbacks = []
    asks = []
    sandbox_bypasses = []

    for r in records:
        hook_out = r.get("hook_output", {})
        dec = hook_out.get("decision", "").lower()
        reason = hook_out.get("reason", "")
        tool = r.get("toolCall", {}).get("name", "unknown")
        args = r.get("toolCall", {}).get("args", {})
        target = args.get("CommandLine") or args.get("TargetFile") or json.dumps(args)[:60]
        classification = r.get("classification", {})
        latency = classification.get("latency_ms", 0.0)
        risk_cat = classification.get("risk_category", "")
        bypass_sandbox = args.get("BypassSandbox", False)

        if dec == "deny":
            denials.append(
                {
                    "tool": tool,
                    "target": target,
                    "reason": reason,
                    "risk_category": risk_cat,
                }
            )
        elif dec in ("ask", "force_ask"):
            asks.append(
                {
                    "tool": tool,
                    "target": target,
                    "reason": reason,
                    "risk_category": risk_cat,
                }
            )

        if bypass_sandbox is True and dec == "allow":
            sandbox_bypasses.append(
                {
                    "tool": tool,
                    "target": target,
                    "reason": reason,
                }
            )

        if latency > 2000.0 and "static_policy" not in risk_cat:
            high_latency.append({"tool": tool, "target": target, "latency_ms": latency})

        if risk_cat in ("missing_credentials", "classifier_error"):
            error_fallbacks.append({"reason": reason, "risk_category": risk_cat})

    recommendations = []
    if denials:
        recommendations.append(
            f"Found {len(denials)} denied action(s). If these actions are intended, use "
            "`python3 skills/auto-permissions-fix/scripts/fix_permissions.py --last --allow` "
            "to generate ACL rules."
        )
    if sandbox_bypasses:
        recommendations.append(
            f"{len(sandbox_bypasses)} action(s) were approved by the gate but required "
            "Host Sandbox Elevation (`BypassSandbox: true`), which prompts the IDE platform. "
            "Select 'Always allow for this workspace' on the prompt modal for unattended runs."
        )
    if error_fallbacks:
        recommendations.append(
            "Classifier fallback detected (missing GEMINI_API_KEY or connection error). "
            "Ensure GEMINI_API_KEY is exported in your environment."
        )
    if high_latency:
        recommendations.append(
            f"{len(high_latency)} call(s) had high latency (>2000ms). Consider adding static "
            "ACL rules in `.agents/auto-permissions.json` for frequent commands to enable "
            "0.1ms fast-path execution."
        )

    return {
        "total_evaluated": total,
        "denials": denials,
        "asks": asks,
        "sandbox_bypasses": sandbox_bypasses,
        "high_latency": high_latency,
        "error_fallbacks": error_fallbacks,
        "recommendations": recommendations,
    }


def generate_markdown_summary(
    records: list[dict[str, Any]],
    limit: int = 10,
    since_step_idx: int | None = None,
    turn_scoped: bool = False,
) -> str | None:
    """Generates a compact, collapsible Markdown summary table of recent decisions."""
    if not records:
        return None

    if turn_scoped and since_step_idx is not None:
        subset = [r for r in records if r.get("stepIdx", 0) >= since_step_idx]
        if not subset:
            return None
        header_scope = "in this turn"
    else:
        subset = records[-limit:]
        if not subset:
            return None
        header_scope = "evaluated"

    allowed = sum(
        1 for r in subset if r.get("hook_output", {}).get("decision", "").lower() == "allow"
    )
    denied = sum(
        1 for r in subset if r.get("hook_output", {}).get("decision", "").lower() == "deny"
    )
    asked = len(subset) - allowed - denied

    header_status = f"{len(subset)} actions {header_scope} ({allowed} allowed, {denied} denied"
    if asked > 0:
        header_status += f", {asked} escalated"
    header_status += ")"

    rows = []
    for r in subset:
        tool = r.get("toolCall", {}).get("name", "unknown")
        args = r.get("toolCall", {}).get("args", {})
        raw_cmd = args.get("CommandLine") or args.get("TargetFile") or json.dumps(args)
        # Collapse all newlines, carriage returns, tabs, and backticks into single-line snippet
        cleaned_cmd = " ".join(raw_cmd.replace("`", "").split()).strip()
        cmd_snippet = cleaned_cmd[:42] + "..." if len(cleaned_cmd) > 45 else cleaned_cmd
        # Escape pipe so the Target cell cannot split the Markdown table columns.
        cmd_snippet = cmd_snippet.replace("|", "\\|")

        dec = r.get("hook_output", {}).get("decision", "unknown").lower()
        if dec == "allow":
            badge = "🟢 **ALLOW**"
        elif dec == "deny":
            badge = "🔴 **DENY**"
        else:
            badge = "🟡 **ASK**"

        classification = r.get("classification", {})
        risk_cat = classification.get("risk_category", "")
        latency = classification.get("latency_ms", 0.0)
        provider = str(classification.get("provider", "antigravity")).lower()
        if provider == "antigravity":
            provider_name = "Antigravity"
        elif provider == "cloudcode":
            provider_name = "Cloud Code"
        elif provider == "anthropic":
            provider_name = "Claude"
        elif provider == "openai":
            provider_name = "OpenAI"
        else:
            provider_name = "Gemini"

        if "static_policy" in risk_cat:
            mode_str = f"Static ACL ({latency:.1f}ms)"
        elif "intra_turn_cache" in risk_cat:
            mode_str = f"Turn Cache ({latency:.1f}ms)"
        elif "same_turn_file_grant" in risk_cat:
            mode_str = f"File Grant ({latency:.1f}ms)"
        elif "circuit_breaker" in risk_cat:
            mode_str = f"⚠️ Circuit Breaker ({latency:.1f}ms)"
        elif "workspace_write" in risk_cat:
            mode_str = f"Workspace Write ({latency:.1f}ms)"
        elif "safe_read_command" in risk_cat:
            mode_str = f"Safe Read ({latency:.1f}ms)"
        elif "ungoverned_surface" in risk_cat:
            mode_str = f"Opt-in Surface ({latency:.1f}ms)"
        elif "classifier_error" in risk_cat or classification.get("error"):
            reason = r.get("hook_output", {}).get("reason", "") or classification.get("reason", "")
            err_tag = "Offline"
            if "HTTP 401" in reason or "401" in reason:
                err_tag = "HTTP 401"
            elif "HTTP 404" in reason or "404" in reason:
                err_tag = "HTTP 404"
            elif "HTTP 403" in reason or "403" in reason:
                err_tag = "HTTP 403"
            elif "HTTP 5" in reason or "500" in reason or "502" in reason or "503" in reason:
                err_tag = "HTTP 5xx"
            elif "timed out" in reason.lower() or "timeout" in reason.lower():
                err_tag = "Timeout"
            elif "refused" in reason.lower():
                err_tag = "Offline"
            elif "not configured" in reason.lower() or "missing" in reason.lower():
                err_tag = "No Key"
            mode_str = f"⚠️ Fallback ({err_tag} / {latency:.0f}ms)"
        else:
            mode_str = f"{provider_name} ({latency:.0f}ms)"

        rows.append(f"| `{tool}` | `{cmd_snippet}` | {badge} | {mode_str} |")

    table_body = "\n".join(rows)

    return f"""<details>
<summary>🛡️ <b>Security Gate Summary:</b> {header_status}</summary>

| Tool Action | Target | Verdict | Evaluation Mode |
| :--- | :--- | :---: | :--- |
{table_body}

</details>"""
