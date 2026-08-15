#!/usr/bin/env python3
"""
Transcript Parser for Google Antigravity Auto-Permissions Hook.
Extracts user prompt history from transcript.jsonl with zero assistant CoT or tool leakage.
"""

import contextlib
import json
import os


def sanitize_user_prompt(text: str) -> str:
    """
    Extracts strictly the core user request, stripping volatile metadata,
    timestamps, and settings change envelopes for byte-stable prompt caching.
    """
    if not text:
        return ""

    # Extract content within <USER_REQUEST> if present
    if "<USER_REQUEST>" in text and "</USER_REQUEST>" in text:
        start = text.find("<USER_REQUEST>") + len("<USER_REQUEST>")
        end = text.find("</USER_REQUEST>", start)
        if end != -1:
            text = text[start:end].strip()

    # Strip any remaining XML envelope wrappers
    for tag in ("ADDITIONAL_METADATA", "USER_SETTINGS_CHANGE", "SKILL"):
        open_tag = f"<{tag}>"
        close_tag = f"</{tag}>"
        while open_tag in text and close_tag in text:
            start = text.find(open_tag)
            end = text.find(close_tag, start) + len(close_tag)
            text = (text[:start] + text[end:]).strip()

    return text.strip()


def extract_user_content(step_obj: dict) -> str | None:
    """Extracts raw text from a transcript step JSON object if it is a user input."""
    step_type = step_obj.get("type", "")
    source = step_obj.get("source", "")

    if step_type in ("USER_INPUT", "USER_MESSAGE") or source in ("USER_EXPLICIT", "USER"):
        content = step_obj.get("content", "")
        raw_text = ""
        if isinstance(content, str):
            raw_text = content.strip()
        elif isinstance(content, list):
            texts = []
            for part in content:
                if isinstance(part, str):
                    texts.append(part)
                elif isinstance(part, dict) and "text" in part:
                    texts.append(part["text"])
            raw_text = "\n".join(texts).strip()
        elif isinstance(content, dict) and "text" in content:
            raw_text = str(content["text"]).strip()

        if raw_text:
            cleaned = sanitize_user_prompt(raw_text)
            return cleaned or raw_text
    return None


def read_user_prompts_from_transcript(
    transcript_path: str, max_history: int = 4
) -> tuple[list[str], str | None]:
    """
    Parses transcript.jsonl to extract prior user prompts and the active user prompt.
    Labels prior turns with absolute chronological turn numbers ([Turn 0], [Turn 1], ...)
    to guarantee byte-stable prefix caching across turns.

    Returns:
        Tuple of (prior_prompts, active_prompt):
        - prior_prompts: List of labeled previous user prompts (Turn 0 anchor + rolling turns)
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

    total_priors = len(all_priors)
    if total_priors <= max_history:
        # Absolute chronological labeling: [Turn 0], [Turn 1], ...
        prior_prompts = [f"[Turn {i}]: {p}" for i, p in enumerate(all_priors)]
        return prior_prompts, active_prompt

    # Conversation exceeds max_history: preserve Turn 0 Session Goal + rolling recent turns
    # Turn 0 anchor remains [Turn 0]: ...
    # Recent turns preserve their exact original turn index (e.g. [Turn 6], [Turn 7], ...)
    start_recent_idx = total_priors - max_history
    session_anchor = all_priors[0]

    prior_prompts = [f"[Turn 0 / Anchor]: {session_anchor}"]
    for idx in range(start_recent_idx, total_priors):
        if idx == 0:
            continue
        prior_prompts.append(f"[Turn {idx}]: {all_priors[idx]}")

    return prior_prompts, active_prompt


def get_last_user_step_index(transcript_path: str) -> int | None:
    """
    Finds the step index of the most recent user prompt in transcript.jsonl.
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return None

    last_step_idx = None
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    step = json.loads(line)
                    text = extract_user_content(step)
                    if text is not None:
                        last_step_idx = step.get("step_index", step.get("step_idx", 0))
    except Exception:
        return None
    return last_step_idx
