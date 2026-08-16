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
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from audit_logger import (  # noqa: E402
    log_audit_event_async,
    resolve_session_log_path,
    resolve_session_root_dir,
)
from classifier import classify_tool_call  # noqa: E402
from policy_engine import (  # noqa: E402
    check_intra_turn_cache,
    check_same_turn_file_grant,
    evaluate_static_policies,
    evaluate_workspace_write_fast_path,
    is_safe_read_only_command,
    is_ungoverned_surface,
    load_custom_guidelines,
    resolve_classifier_config,
)
from transcript_parser import (  # noqa: E402
    get_last_user_step_index,
    read_user_prompts_from_transcript,
)


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
    conversation_id = payload.get("conversationId") or payload.get("conversation_id", "")
    workspace_paths = payload.get("workspacePaths") or payload.get("workspace_paths", [])
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

    # Extract optional explicit goal object or string
    raw_goal = (
        payload.get("goal")
        or payload.get("sessionGoal")
        or payload.get("activeGoal")
        or payload.get("session_goal")
    )
    if isinstance(raw_goal, dict):
        session_goal = (
            raw_goal.get("description")
            or raw_goal.get("text")
            or raw_goal.get("goal")
            or json.dumps(raw_goal)
        )
    elif isinstance(raw_goal, str):
        session_goal = raw_goal.strip()
    else:
        session_goal = None

    # Resolve session directory for overrides and audit logging
    log_path = resolve_session_log_path(artifact_dir, transcript_path, conversation_id)
    session_dir = resolve_session_root_dir(
        artifact_dir, transcript_path, conversation_id, log_path
    ) or os.path.dirname(os.path.abspath(log_path))

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

    # 2. FAST-PATH: Opt-in surface verification (subagents, schedule, images)
    if is_ungoverned_surface(
        tool_name=tool_name,
        session_dir=session_dir,
        workspace_paths=workspace_paths,
    ):
        ungoverned_reason = f"Tool '{tool_name}' is fast-path approved (surface not opted in)."
        hook_output = {
            "decision": "allow",
            "reason": ungoverned_reason,
        }
        classification = {
            "decision": "allow",
            "reason": ungoverned_reason,
            "risk_category": "ungoverned_surface_opt_in",
            "confidence": 1.0,
        }
        context_summary = {
            "active_prompt": "(Opt-in surface not enabled)",
            "prior_prompts_count": 0,
            "workspace_roots": workspace_paths,
            "policy_scope": "ungoverned_surface",
        }
        log_thread = log_audit_event_async(
            artifact_dir=artifact_dir,
            transcript_path=transcript_path,
            conversation_id=conversation_id,
            step_idx=step_idx,
            tool_call=tool_call,
            context=context_summary,
            raw_prompt=f"<ungoverned_surface tool='{tool_name}'/>",
            classification=classification,
            hook_output=hook_output,
            latency_ms=0.1,
        )
        print(json.dumps(hook_output))
        sys.stdout.flush()
        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=0.2)
        return

    # 3. FAST-PATH: Safe Read-Only CLI Command Fast-Path
    if tool_name == "run_command":
        cmd_str = tool_args.get("CommandLine", "")
        if is_safe_read_only_command(cmd_str, workspace_paths=workspace_paths):
            safe_read_reason = (
                f"Read-only utility '{cmd_str.split()[0]}' is safe (inspection pipeline)."
            )
            hook_output = {
                "decision": "allow",
                "reason": safe_read_reason,
            }
            classification = {
                "decision": "allow",
                "reason": safe_read_reason,
                "risk_category": "safe_read_command",
                "confidence": 1.0,
            }
            context_summary = {
                "active_prompt": "(Safe read-only command fast-path)",
                "prior_prompts_count": 0,
                "workspace_roots": workspace_paths,
                "policy_scope": "safe_read_command",
            }
            log_thread = log_audit_event_async(
                artifact_dir=artifact_dir,
                transcript_path=transcript_path,
                conversation_id=conversation_id,
                step_idx=step_idx,
                tool_call=tool_call,
                context=context_summary,
                raw_prompt=f"<safe_read_command command='{cmd_str}'/>",
                classification=classification,
                hook_output=hook_output,
                latency_ms=0.1,
            )
            print(json.dumps(hook_output))
            sys.stdout.flush()
            if log_thread and log_thread.is_alive():
                log_thread.join(timeout=0.2)
            return

    # 4. FAST-PATH: Check Intra-Turn Decision Cache
    last_user_step_idx = get_last_user_step_index(transcript_path)
    cached_verdict = check_intra_turn_cache(
        tool_name=tool_name,
        tool_args=tool_args,
        log_path=log_path,
        last_user_step_idx=last_user_step_idx,
    )
    if cached_verdict:
        cached_decision, cached_reason = cached_verdict
        hook_output = {
            "decision": cached_decision,
            "reason": cached_reason,
        }
        classification = {
            "decision": cached_decision,
            "reason": cached_reason,
            "risk_category": "intra_turn_cache",
            "confidence": 1.0,
        }
        context_summary = {
            "active_prompt": "(Intra-turn exact match cache)",
            "prior_prompts_count": 0,
            "workspace_roots": workspace_paths,
            "policy_scope": "intra_turn_cache",
        }
        log_thread = log_audit_event_async(
            artifact_dir=artifact_dir,
            transcript_path=transcript_path,
            conversation_id=conversation_id,
            step_idx=step_idx,
            tool_call=tool_call,
            context=context_summary,
            raw_prompt=f"<intra_turn_cache tool='{tool_name}' decision='{cached_decision}'/>",
            classification=classification,
            hook_output=hook_output,
            latency_ms=0.1,
        )
        print(json.dumps(hook_output))
        sys.stdout.flush()
        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=0.2)
        return

    # 5. FAST-PATH: Same-Turn File Mutation Grant
    file_grant = check_same_turn_file_grant(
        tool_name=tool_name,
        tool_args=tool_args,
        log_path=log_path,
        last_user_step_idx=last_user_step_idx,
        workspace_paths=workspace_paths,
    )
    if file_grant:
        grant_decision, grant_reason = file_grant
        hook_output = {
            "decision": grant_decision,
            "reason": grant_reason,
        }
        classification = {
            "decision": grant_decision,
            "reason": grant_reason,
            "risk_category": "same_turn_file_grant",
            "confidence": 1.0,
        }
        context_summary = {
            "active_prompt": "(Same-turn target file grant)",
            "prior_prompts_count": 0,
            "workspace_roots": workspace_paths,
            "policy_scope": "same_turn_file_grant",
        }
        target_f = tool_args.get("TargetFile")
        log_thread = log_audit_event_async(
            artifact_dir=artifact_dir,
            transcript_path=transcript_path,
            conversation_id=conversation_id,
            step_idx=step_idx,
            tool_call=tool_call,
            context=context_summary,
            raw_prompt=f"<same_turn_file_grant tool='{tool_name}' file='{target_f}'/>",
            classification=classification,
            hook_output=hook_output,
            latency_ms=0.1,
        )
        print(json.dumps(hook_output))
        sys.stdout.flush()
        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=0.2)
        return

    # 6. FAST-PATH: Safe Workspace File Writes (trust_workspace_writes)
    write_fast_path = evaluate_workspace_write_fast_path(
        tool_name=tool_name,
        tool_args=tool_args,
        workspace_paths=workspace_paths,
        session_dir=session_dir,
    )
    if write_fast_path:
        write_decision, write_reason, write_scope = write_fast_path
        hook_output = {
            "decision": write_decision,
            "reason": write_reason,
        }
        classification = {
            "decision": write_decision,
            "reason": write_reason,
            "risk_category": "workspace_write_fast_path",
            "confidence": 1.0,
        }
        context_summary = {
            "active_prompt": "(Safe workspace write fast-path)",
            "prior_prompts_count": 0,
            "workspace_roots": workspace_paths,
            "policy_scope": "workspace_write_fast_path",
        }
        target_f = (
            tool_args.get("TargetFile")
            or tool_args.get("target_file")
            or tool_args.get("AbsolutePath")
            or tool_args.get("path")
        )
        log_thread = log_audit_event_async(
            artifact_dir=artifact_dir,
            transcript_path=transcript_path,
            conversation_id=conversation_id,
            step_idx=step_idx,
            tool_call=tool_call,
            context=context_summary,
            raw_prompt=f"<workspace_write_fast_path tool='{tool_name}' file='{target_f}'/>",
            classification=classification,
            hook_output=hook_output,
            latency_ms=0.1,
        )
        print(json.dumps(hook_output))
        sys.stdout.flush()
        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=0.2)
        return

    # 7. Parse user prompt history from transcript.jsonl
    prior_prompts, active_prompt = read_user_prompts_from_transcript(transcript_path, max_history=4)

    # 8. Load custom semantic guidelines from policy configurations
    custom_guidelines = load_custom_guidelines(
        workspace_paths=workspace_paths,
        session_dir=session_dir,
    )

    # 4. Resolve configured classifier settings (provider, model, endpoint_url, api_key)
    classifier_cfg = resolve_classifier_config(
        session_dir=session_dir,
        workspace_paths=workspace_paths,
    )

    # 5. Invoke security classifier
    raw_prompt, classification, error, latency_ms = classify_tool_call(
        workspace_paths=workspace_paths,
        prior_prompts=prior_prompts,
        active_prompt=active_prompt or "",
        tool_name=tool_name,
        tool_args=tool_args,
        tool_action=tool_action,
        tool_summary=tool_summary,
        custom_guidelines=custom_guidelines,
        session_goal=session_goal,
        provider=classifier_cfg["provider"],
        model=classifier_cfg["model"],
        endpoint_url=classifier_cfg["endpoint_url"],
        api_key=classifier_cfg["api_key"],
        timeout_secs=classifier_cfg.get("timeout_secs", 6.0),
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
    if session_goal:
        context_summary["session_goal"] = session_goal

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
