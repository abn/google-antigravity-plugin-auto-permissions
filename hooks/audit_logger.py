#!/usr/bin/env python3
"""
Thread-safe, rotatable asynchronous audit logger for Google Antigravity Auto-Permissions Hook.
Records JSON Lines audit traces in the session directory and provides summary helpers.
"""

import contextlib
import datetime
import json
import os
import threading
from typing import Any

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_BACKUP_COUNT = 3


def resolve_session_log_path(
    artifact_dir: str | None = None,
    transcript_path: str | None = None,
    conversation_id: str | None = None,
) -> str:
    """Resolves the canonical path for audit.jsonl within the active session directory."""
    if artifact_dir:
        target_dir = os.path.abspath(os.path.expanduser(artifact_dir))
        os.makedirs(target_dir, exist_ok=True)
        return os.path.join(target_dir, "audit.jsonl")

    if transcript_path:
        norm_path = os.path.abspath(os.path.expanduser(transcript_path))
        parent = os.path.dirname(norm_path)
        if parent.endswith(".system_generated/logs") or parent.endswith(".system_generated/logs/"):
            session_dir = os.path.abspath(os.path.join(parent, "../.."))
            os.makedirs(session_dir, exist_ok=True)
            return os.path.join(session_dir, "audit.jsonl")
        elif parent:
            os.makedirs(parent, exist_ok=True)
            return os.path.join(parent, "audit.jsonl")

    cid = conversation_id or "default_session"
    home_dir = os.path.expanduser("~")
    fallback_dir = os.path.join(home_dir, ".gemini", "antigravity", "brain", cid)
    with contextlib.suppress(OSError):
        os.makedirs(fallback_dir, exist_ok=True)
        return os.path.join(fallback_dir, "audit.jsonl")

    # Safe fallback if home directory is read-only in sandbox
    tmp_fallback = os.path.join("/tmp", f"antigravity_audit_{cid}")
    with contextlib.suppress(OSError):
        os.makedirs(tmp_fallback, exist_ok=True)
        return os.path.join(tmp_fallback, "audit.jsonl")

    return os.path.abspath("./audit.jsonl")


def rotate_log_file_if_needed(file_path: str, max_bytes: int, backup_count: int) -> None:
    """Rotates log file if it exceeds max_bytes (e.g. audit.jsonl -> audit.1.jsonl)."""
    if not os.path.exists(file_path):
        return

    try:
        if os.path.getsize(file_path) < max_bytes:
            return

        for i in range(backup_count - 1, 0, -1):
            sfn = f"{file_path}.{i}"
            dfn = f"{file_path}.{i + 1}"
            if os.path.exists(sfn):
                if os.path.exists(dfn):
                    os.remove(dfn)
                os.rename(sfn, dfn)

        dfn = f"{file_path}.1"
        if os.path.exists(dfn):
            os.remove(dfn)
        os.rename(file_path, dfn)
    except Exception:
        # Ignore rotation race conditions or permissions issues gracefully
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


def generate_markdown_summary(records: list[dict[str, Any]], limit: int = 5) -> str:
    """Generates a compact, collapsible Markdown summary table of recent decisions."""
    if not records:
        return "🛡️ *No security gate decisions recorded for this session.*"

    subset = records[-limit:]
    allowed = sum(
        1 for r in subset if r.get("hook_output", {}).get("decision", "").lower() == "allow"
    )
    denied = sum(
        1 for r in subset if r.get("hook_output", {}).get("decision", "").lower() == "deny"
    )
    asked = len(subset) - allowed - denied

    header_status = f"{len(subset)} actions evaluated ({allowed} allowed, {denied} denied"
    if asked > 0:
        header_status += f", {asked} escalated"
    header_status += ")"

    rows = []
    for r in subset:
        tool = r.get("toolCall", {}).get("name", "unknown")
        args = r.get("toolCall", {}).get("args", {})
        raw_cmd = args.get("CommandLine") or args.get("TargetFile") or json.dumps(args)
        cmd_snippet = raw_cmd.replace("`", "").strip()
        if len(cmd_snippet) > 45:
            cmd_snippet = cmd_snippet[:42] + "..."

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

        if "static_policy" in risk_cat:
            mode_str = f"Static ACL ({latency:.1f}ms)"
        else:
            mode_str = f"Gemini ({latency:.0f}ms)"

        rows.append(f"| `{tool}` | `{cmd_snippet}` | {badge} | {mode_str} |")

    table_body = "\n".join(rows)

    return f"""<details>
<summary>🛡️ <b>Security Gate Summary:</b> {header_status}</summary>

| Tool Action | Target | Verdict | Evaluation Mode |
| :--- | :--- | :---: | :--- |
{table_body}

</details>"""
