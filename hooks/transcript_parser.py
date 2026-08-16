#!/usr/bin/env python3
"""
Transcript Parser for Google Antigravity Auto-Permissions Hook.
Extracts user prompt history from transcript.jsonl with zero assistant CoT or tool leakage.
"""

import contextlib
import json
import os
import re

STRIP_BLOCK_REGEX = re.compile(
    r"<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE|SKILL|workspace_roots|custom_workspace_guidelines|session_goal|prior_user_prompts|proposed_tool_call|static_policy_match|circuit_breaker|intra_turn_cache|same_turn_file_grant|workspace_write_fast_path)>[\s\S]*?</(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE|SKILL|workspace_roots|custom_workspace_guidelines|session_goal|prior_user_prompts|proposed_tool_call|static_policy_match|circuit_breaker|intra_turn_cache|same_turn_file_grant|workspace_write_fast_path)>",
    re.IGNORECASE,
)
UNWRAP_CONTAINER_REGEX = re.compile(
    r"<(?:USER_REQUEST|active_user_prompt)>([\s\S]*?)</(?:USER_REQUEST|active_user_prompt)>",
    re.IGNORECASE,
)


def sanitize_user_prompt(text: str) -> str:
    """
    Extracts strictly the core user request in single-pass O(N) regex, stripping
    volatile metadata and auxiliary envelopes without CPU saturation.
    """
    if not text:
        return ""

    # 1. Strip metadata blocks and auxiliary sections completely
    cleaned = STRIP_BLOCK_REGEX.sub("", text).strip()

    # 2. Unwrap container tags (<USER_REQUEST> and <active_user_prompt>) up to 5 levels
    for _ in range(5):
        prev = cleaned
        cleaned = re.sub(
            r"^\s*<(?:USER_REQUEST|active_user_prompt)>\s*", "", cleaned, flags=re.IGNORECASE
        )
        cleaned = re.sub(
            r"\s*</(?:USER_REQUEST|active_user_prompt)>\s*$", "", cleaned, flags=re.IGNORECASE
        )
        if cleaned == prev:
            break

    return cleaned.strip()


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


def _read_tail_lines(file_path: str, max_bytes: int = 128 * 1024) -> list[str]:
    """Reads the last max_bytes of a file in O(1) time without parsing the full file."""
    if not file_path or not os.path.isfile(file_path):
        return []
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            if file_size > max_bytes:
                f.seek(file_size - max_bytes)
                f.readline()  # Discard partial first line
            raw_data = f.read()
            return raw_data.decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []


def read_user_prompts_from_transcript(
    transcript_path: str, max_history: int = 4
) -> tuple[list[str], str | None]:
    """
    Parses transcript.jsonl to extract prior user prompts and active user prompt.
    Uses tail-seeking to guarantee ultra-low latency (<1ms) on large transcripts.
    """
    lines = _read_tail_lines(transcript_path)
    if not lines:
        return [], None

    user_prompts = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            step = json.loads(line)
            text = extract_user_content(step)
            if text:
                user_prompts.append(text)

    if not user_prompts:
        return [], None

    active_prompt = user_prompts[-1]
    all_priors = user_prompts[:-1]

    if not all_priors:
        return [], active_prompt

    total_priors = len(all_priors)
    if total_priors <= max_history:
        prior_prompts = [f"[Turn {i}]: {p}" for i, p in enumerate(all_priors)]
        return prior_prompts, active_prompt

    start_recent_idx = total_priors - max_history
    session_anchor = all_priors[0]

    prior_prompts = [f"[Turn 0]: {session_anchor}"]
    for idx in range(start_recent_idx, total_priors):
        if idx == 0:
            continue
        prior_prompts.append(f"[Turn {idx}]: {all_priors[idx]}")

    return prior_prompts, active_prompt


def get_last_user_step_index(transcript_path: str) -> int | None:
    """
    Finds the step index of the most recent user prompt in transcript.jsonl.
    Scans lines in reverse for instantaneous O(1) response time.
    """
    lines = _read_tail_lines(transcript_path)
    if not lines:
        return None

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            step = json.loads(line)
            text = extract_user_content(step)
            if text is not None:
                return step.get("step_index", step.get("step_idx", 0))

    return None
