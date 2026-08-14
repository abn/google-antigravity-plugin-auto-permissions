#!/usr/bin/env python3
"""
Transcript Parser for Google Antigravity Auto-Permissions Hook.
Extracts user prompt history from transcript.jsonl with zero assistant CoT or tool leakage.
"""

import contextlib
import json
import os


def extract_user_content(step_obj: dict) -> str | None:
    """Extracts raw text from a transcript step JSON object if it is a user input."""
    step_type = step_obj.get("type", "")
    source = step_obj.get("source", "")

    if step_type in ("USER_INPUT", "USER_MESSAGE") or source in ("USER_EXPLICIT", "USER"):
        content = step_obj.get("content", "")
        if isinstance(content, str):
            text = content.strip()
            if text:
                return text
        elif isinstance(content, list):
            texts = []
            for part in content:
                if isinstance(part, str):
                    texts.append(part)
                elif isinstance(part, dict) and "text" in part:
                    texts.append(part["text"])
            combined = "\n".join(texts).strip()
            if combined:
                return combined
        elif isinstance(content, dict) and "text" in content:
            text = str(content["text"]).strip()
            if text:
                return text
    return None


def read_user_prompts_from_transcript(
    transcript_path: str, max_history: int = 4
) -> tuple[list[str], str | None]:
    """
    Parses transcript.jsonl to extract prior user prompts and the active user prompt.
    Preserves initial Turn 0 (Session Goal / Anchor) if conversation exceeds max_history turns.

    Returns:
        Tuple of (prior_prompts, active_prompt):
        - prior_prompts: List of previous user prompts (Turn 0 anchor + rolling recent turns)
        - active_prompt: Most recent user prompt, or None if not found
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return [], None

    user_prompts = []
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    step = json.loads(line)
                    text = extract_user_content(step)
                    if text:
                        user_prompts.append(text)
    except Exception:
        return [], None

    if not user_prompts:
        return [], None

    active_prompt = user_prompts[-1]
    all_priors = user_prompts[:-1]

    if not all_priors:
        return [], active_prompt

    if len(all_priors) <= max_history:
        return all_priors, active_prompt

    # Conversation exceeds max_history: preserve Turn 0 Session Goal + rolling recent turns
    session_anchor = all_priors[0]
    rolling_recent = all_priors[-max_history:]

    if session_anchor not in rolling_recent:
        prior_prompts = [f"[Session Goal / Turn 0]: {session_anchor}"] + rolling_recent
    else:
        prior_prompts = rolling_recent

    return prior_prompts, active_prompt
