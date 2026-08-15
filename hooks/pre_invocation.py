#!/usr/bin/env python3
"""
PreInvocation Hook for Google Antigravity Auto-Permissions Plugin.
Inspects active session audit records and injects a transient ephemeral summary reminder
into the conversation trajectory before the model generates its response.
"""

import contextlib
import json
import os
import sys

# Ensure local hooks package is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from audit_logger import (  # noqa: E402
    generate_markdown_summary,
    load_audit_records,
    resolve_session_log_path,
    resolve_session_root_dir,
)
from policy_engine import resolve_show_turn_summary  # noqa: E402
from transcript_parser import get_last_user_step_index  # noqa: E402


def main():
    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin or not raw_stdin.strip():
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()
            return

        payload = json.loads(raw_stdin)
    except Exception:
        print(json.dumps({"injectSteps": []}))
        sys.stdout.flush()
        return

    try:
        conversation_id = payload.get("conversationId") or payload.get("conversation_id", "")
        transcript_path = (
            payload.get("transcriptPath")
            or payload.get("transcript_path")
            or payload.get("logPath")
            or payload.get("log_path")
            or ""
        )
        artifact_dir = (
            payload.get("artifactDirectoryPath")
            or payload.get("artifact_dir")
            or payload.get("artifactDir")
            or ""
        )
        workspace_paths = payload.get("workspacePaths") or payload.get("workspace_paths", [])

        log_path = resolve_session_log_path(artifact_dir, transcript_path, conversation_id)
        session_dir = resolve_session_root_dir(
            artifact_dir, transcript_path, conversation_id, log_path
        ) or os.path.dirname(os.path.abspath(log_path))

        # Check if turn summary disclosure is enabled (opt-out hierarchy)
        if not resolve_show_turn_summary(session_dir=session_dir, workspace_paths=workspace_paths):
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()
            return

        records = load_audit_records(log_path)

        if not records:
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()
            return

        # Find starting step index of the active user turn
        last_user_step_idx = get_last_user_step_index(transcript_path)

        # Generate turn-scoped Markdown summary (records evaluated since active prompt)
        md_summary = generate_markdown_summary(
            records=records,
            since_step_idx=last_user_step_idx,
            turn_scoped=True,
        )

        # If no security gate actions were evaluated during this turn, suppress summary
        if not md_summary:
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()
            return

        ephemeral_text = (
            "The security gate evaluated tool actions during this active turn. "
            "Append ONLY the exact collapsible Markdown summary below at the very end of your "
            "final response to the user. If you are outputting an intermediate progress update "
            "(such as waiting for a background task or subagent), do NOT include this summary. "
            "Do not include headers, titles, or preamble text:\n\n"
            f"{md_summary}\n"
        )

        output = {
            "injectSteps": [
                {
                    "ephemeralMessage": ephemeral_text,
                }
            ]
        }
        print(json.dumps(output))
        sys.stdout.flush()

    except Exception:
        # Never block invocation on hook errors
        with contextlib.suppress(Exception):
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
