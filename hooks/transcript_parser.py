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


DEFAULT_CHUNK_SIZE = 256 * 1024  # 256 KB


def read_user_prompts_from_transcript(
    transcript_path: str, max_history: int = 4
) -> tuple[list[str], str | None]:
    """
    Parses transcript.jsonl to extract prior user prompts and active user prompt.
    Labels prior turns with absolute chronological turn numbers ([Turn 0], [Turn 1], ...)
    to guarantee byte-stable prefix caching across turns.
    Preserves Turn 0 session anchor across large conversations regardless of output volume.
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return [], None

    user_prompts: list[str] = []
    try:
        with open(transcript_path, "rb") as f:
            for line in f:
                if b'"USER' not in line and b'"user' not in line:
                    continue
                with contextlib.suppress(Exception):
                    step = json.loads(line.decode("utf-8", errors="replace"))
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
    Scans backward in blocks for instantaneous O(1) response time without buffer cutoffs.
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return None

    try:
        file_size = os.path.getsize(transcript_path)
        if file_size == 0:
            return None

        chunk_size = DEFAULT_CHUNK_SIZE
        offset = file_size
        remainder = b""

        with open(transcript_path, "rb") as f:
            while offset > 0:
                read_size = min(chunk_size, offset)
                offset -= read_size
                f.seek(offset)
                chunk = f.read(read_size) + remainder
                lines = chunk.splitlines()

                if offset > 0 and lines:
                    remainder = lines[0]
                    lines = lines[1:]
                else:
                    remainder = b""

                for line in reversed(lines):
                    if b'"USER' not in line and b'"user' not in line:
                        continue
                    with contextlib.suppress(Exception):
                        step = json.loads(line.decode("utf-8", errors="replace"))
                        text = extract_user_content(step)
                        if text is not None:
                            return step.get("step_index", step.get("step_idx", 0))

                chunk_size = min(chunk_size * 2, 2 * 1024 * 1024)
    except Exception:
        return None

    return None
