#!/usr/bin/env python3
"""
Main PreToolUse Gate Script for Google Antigravity Auto-Permissions Plugin.
Reads toolCall JSON from stdin, performs hierarchical fast-path static policy evaluation,
invokes Gemini security classifier if unconfigured, logs audit trace asynchronously,
and outputs authorization decision JSON on stdout.
"""

import json
import os
import sys

# Ensure local hooks package is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from audit_logger import log_audit_event_async, resolve_session_log_path  # noqa: E402
from classifier import classify_tool_call  # noqa: E402
from policy_engine import evaluate_static_policies, load_custom_guidelines  # noqa: E402
from transcript_parser import read_user_prompts_from_transcript  # noqa: E402


def main():
    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin or not raw_stdin.strip():
            output = {
                "decision": "ask",
                "reason": "Auto-permissions gate received empty input on stdin.",
            }
            print(json.dumps(output))
            sys.stdout.flush()
            return

        payload = json.loads(raw_stdin)
    except Exception as exc:
        output = {
            "decision": "ask",
            "reason": f"Auto-permissions gate failed to parse stdin JSON: {exc}",
        }
        print(json.dumps(output))
        sys.stdout.flush()
        return

    tool_call = payload.get("toolCall", {})
    tool_name = tool_call.get("name", "unknown")
    tool_args = tool_call.get("args", {})
    tool_action = payload.get("toolAction") or tool_call.get("toolAction")
    tool_summary = payload.get("toolSummary") or tool_call.get("toolSummary")
    step_idx = payload.get("stepIdx", 0)
    conversation_id = payload.get("conversationId", "")
    workspace_paths = payload.get("workspacePaths", [])
    transcript_path = payload.get("transcriptPath", "")
    artifact_dir = payload.get("artifactDirectoryPath", "")

    # Resolve session directory for overrides and audit logging
    log_path = resolve_session_log_path(artifact_dir, transcript_path, conversation_id)
    session_dir = os.path.dirname(os.path.abspath(log_path))

    # 1. FAST-PATH: Evaluate Static Policies (Session -> Project -> Global)
    static_verdict = evaluate_static_policies(
        tool_name=tool_name,
        tool_args=tool_args,
        session_dir=session_dir,
        workspace_paths=workspace_paths,
    )

    if static_verdict:
        decision, reason, scope = static_verdict
        hook_output = {"decision": decision, "reason": reason}
        classification = {
            "decision": decision,
            "reason": reason,
            "risk_category": f"static_policy_{scope}",
            "confidence": 1.0,
        }
        context_summary = {
            "active_prompt": "(Fast-path static policy evaluation)",
            "prior_prompts_count": 0,
            "workspace_roots": workspace_paths,
            "policy_scope": scope,
        }

        # Log fast-path audit record asynchronously
        log_thread = log_audit_event_async(
            artifact_dir=artifact_dir,
            transcript_path=transcript_path,
            conversation_id=conversation_id,
            step_idx=step_idx,
            tool_call=tool_call,
            context=context_summary,
            raw_prompt=f"<static_policy_match scope='{scope}'>{reason}</static_policy_match>",
            classification=classification,
            hook_output=hook_output,
            latency_ms=0.2,
        )

        print(json.dumps(hook_output))
        sys.stdout.flush()
        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=0.2)
        return

    # 2. Parse user prompt history from transcript.jsonl
    prior_prompts, active_prompt = read_user_prompts_from_transcript(transcript_path, max_history=4)

    # 3. Load custom semantic guidelines from policy configurations
    custom_guidelines = load_custom_guidelines(
        workspace_paths=workspace_paths,
        session_dir=session_dir,
    )

    # 4. Invoke Gemini security classifier
    raw_prompt, classification, error, latency_ms = classify_tool_call(
        workspace_paths=workspace_paths,
        prior_prompts=prior_prompts,
        active_prompt=active_prompt or "",
        tool_name=tool_name,
        tool_args=tool_args,
        tool_action=tool_action,
        tool_summary=tool_summary,
        custom_guidelines=custom_guidelines,
    )

    # 4. Map classification verdict to Antigravity PreToolUse decision
    decision_category = classification.get("decision", "ask").lower()
    reason_text = classification.get("reason", "Automated authorization evaluation.")

    if decision_category == "allow":
        hook_decision = "allow"
        hook_reason = reason_text
    elif decision_category in ("soft_deny", "hard_deny"):
        hook_decision = "deny"
        prefix = (
            "Security Gate (Scope Deviation):"
            if decision_category == "soft_deny"
            else "Security Gate Block:"
        )
        hook_reason = f"{prefix} {reason_text}"
    elif decision_category == "force_ask":
        hook_decision = "force_ask"
        hook_reason = reason_text
    else:
        hook_decision = "ask"
        hook_reason = reason_text

    hook_output = {"decision": hook_decision, "reason": hook_reason}

    # 5. Asynchronously write rotatable audit record to session directory
    context_summary = {
        "active_prompt": active_prompt,
        "prior_prompts_count": len(prior_prompts),
        "workspace_roots": workspace_paths,
    }

    log_thread = log_audit_event_async(
        artifact_dir=artifact_dir,
        transcript_path=transcript_path,
        conversation_id=conversation_id,
        step_idx=step_idx,
        tool_call=tool_call,
        context=context_summary,
        raw_prompt=raw_prompt,
        classification=classification,
        hook_output=hook_output,
        latency_ms=latency_ms,
    )

    # Output decision to Antigravity immediately
    print(json.dumps(hook_output))
    sys.stdout.flush()

    # Ensure log worker completes gracefully (max 200ms)
    if log_thread and log_thread.is_alive():
        log_thread.join(timeout=0.2)


if __name__ == "__main__":
    main()
