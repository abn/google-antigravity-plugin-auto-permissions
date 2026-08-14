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
)


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
        conversation_id = payload.get("conversationId", "")
        transcript_path = payload.get("transcriptPath", "")
        artifact_dir = payload.get("artifactDirectoryPath", "")

        log_path = resolve_session_log_path(artifact_dir, transcript_path, conversation_id)
        records = load_audit_records(log_path)

        if not records:
            print(json.dumps({"injectSteps": []}))
            sys.stdout.flush()
            return

        # Generate collapsible Markdown table from recent records
        md_summary = generate_markdown_summary(records, limit=10)

        ephemeral_text = (
            "[Auto-Permissions Security Gate Advisory]\n"
            "The following tool operations were evaluated by the security gate:\n\n"
            f"{md_summary}\n\n"
            "Instruction: At the conclusion of your final response to the user, please append "
            "the collapsible Security Gate Summary above to provide visibility into decisions."
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
