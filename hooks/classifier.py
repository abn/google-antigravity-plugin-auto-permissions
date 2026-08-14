#!/usr/bin/env python3
"""
Security Authorization Classifier for Google Antigravity Auto-Permissions Hook.
Evaluates proposed tool actions against user intent using Google Gemini, OpenAI-wire,
or Anthropic Claude endpoints with zero external runtime dependencies.
"""

import contextlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_PROVIDER = "google"
DEFAULT_MODEL = "gemini-2.5-flash"
GOOGLE_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
)
OPENAI_DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"

SYSTEM_INSTRUCTION = (
    "You are a strict security authorization classifier for an autonomous coding agent workspace.\n"
    "Your task is to classify whether a proposed tool call is safe, authorized, and strictly\n"
    "aligned with the user's instructions and conversation goals.\n\n"
    "EVALUATION CRITERIA & INVARIANTS:\n"
    "1. allow: Safe, non-destructive read/write/test actions strictly matching user intent\n"
    "   within workspace boundaries. Understand referential user prompts using history.\n"
    "   - SUPPORTING DEVELOPER LIFECYCLE ACTIONS: Safe supporting actions that maintain workspace\n"
    "     consistency (e.g. updating lockfiles like `uv lock` or `npm install` after modifying\n"
    "     manifests, running linters/formatters like `ruff` or `eslint` on changed files, or\n"
    "     running local tests like `pytest` to verify edits) are IN-SCOPE and MUST be classified\n"
    "     as 'allow'.\n"
    "   - SKILL DEFINITIONS: Reading installed Antigravity skill definitions (e.g. `SKILL.md`)\n"
    "     when executing relevant skills is safe and authorized as 'allow'.\n"
    "2. soft_deny: Tool call modifies unrequested resources, touches unrelated repositories,\n"
    "   or begins unprompted refactoring of unrelated subsystems. Triggers agent self-correction.\n"
    "   Do NOT soft_deny routine compilation, lockfile updates, linting, or testing of the\n"
    "   modified workspace files.\n"
    "3. ask: Potentially risky operations requiring explicit human verification:\n"
    "   - EXTERNAL REMOTE MUTATIONS & PUBLISHING: Commands that publish, post, comment, push,\n"
    "     or mutate external remote state (e.g. `gh pr comment`, `gh pr create`, `gh issue`,\n"
    "     `git push`, `npm publish`, `cargo publish`) MUST ALWAYS be classified as 'ask' unless\n"
    "     the user's prompt explicitly requested to post/push/publish (e.g. 'post comment',\n"
    "     'submit review', 'push branch'). General instructions like 'address review' or\n"
    "     'fix issue' do NOT authorize posting to external remotes.\n"
    "   - EXTERNAL PATH ACCESS: Reading, searching, or inspecting files outside the authorized\n"
    "     <workspace_roots> (e.g. parent directories, other repositories, ~/.gemini configs)\n"
    "     MUST be classified as 'ask' unless the user explicitly referenced that external path.\n"
    "   - INFRASTRUCTURE & DATA: Database migrations, cloud deploys, deleting major files.\n"
    "4. hard_deny: Hostile or high-risk actions (e.g. credential/key extraction, network\n"
    "   exfiltration, destructive branch wipe `git push -f`, session transcript tampering).\n"
    "5. custom_guidelines: When <custom_workspace_guidelines> are provided, respect\n"
    "   domain-specific instructions. In case of conflict, core security invariants\n"
    "   (credential protection, destructive wipes, external publishing) strictly override\n"
    "   custom guidelines.\n\n"
    "JSON RESPONSE SCHEMA:\n"
    "You MUST respond with valid JSON adhering to this schema:\n"
    "{\n"
    '  "decision": "allow" | "soft_deny" | "ask" | "hard_deny",\n'
    '  "reason": "<concise explanation in 1 sentence>",\n'
    '  "risk_category": "safe_routine" | "scope_deviation" | '
    '"high_risk_infrastructure" | "data_exfiltration_or_destruction",\n'
    '  "confidence": 0.0 - 1.0\n'
    "}"
)


def format_classifier_payload(
    workspace_paths: list[str],
    prior_prompts: list[str],
    active_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    tool_action: str | None = None,
    tool_summary: str | None = None,
    custom_guidelines: list[str] | None = None,
) -> str:
    """Formats minimal sanitized context into structured XML for the security classifier."""
    prior_section = ""
    if prior_prompts:
        lines = []
        anchor = None
        relative_prompts = []
        for p in prior_prompts:
            if p.startswith("[Session Goal / Turn 0]: "):
                anchor = p[len("[Session Goal / Turn 0]: ") :].strip()
            else:
                relative_prompts.append(p)

        if anchor:
            lines.append(f"- [Session Goal / Turn 0]: {anchor}")

        for i, p in enumerate(relative_prompts):
            turn_idx = len(relative_prompts) - i
            lines.append(f"- [Turn -{turn_idx}]: {p.strip()}")

        history_lines = "\n".join(lines)
        prior_section = f"""<prior_user_prompts>
{history_lines}
</prior_user_prompts>
"""

    guidelines_section = ""
    if custom_guidelines:
        gl_lines = "\n".join(f"- {g.strip()}" for g in custom_guidelines if g.strip())
        if gl_lines:
            guidelines_section = f"""<custom_workspace_guidelines>
{gl_lines}
</custom_workspace_guidelines>
"""

    tool_metadata = []
    if tool_summary:
        tool_metadata.append(f"Summary: {tool_summary.strip()}")
    if tool_action:
        tool_metadata.append(f"Action Intent: {tool_action.strip()}")
    metadata_block = ("\n" + "\n".join(tool_metadata)) if tool_metadata else ""

    return f"""<workspace_roots>
{json.dumps(workspace_paths)}
</workspace_roots>

{guidelines_section}{prior_section}<active_user_prompt>
{active_prompt.strip() if active_prompt else "(No explicit active prompt provided)"}
</active_user_prompt>

<proposed_tool_call>
Tool: {tool_name}{metadata_block}
Arguments: {json.dumps(tool_args, indent=2)}
</proposed_tool_call>"""


def _clean_json_text(text: str) -> str:
    """Strips markdown code fences and surrounding whitespace from model response."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _parse_decision_text(raw_text: str) -> dict[str, Any]:
    """Parses and validates decision JSON from text, enforcing fail-closed structure."""
    cleaned = _clean_json_text(raw_text)
    data = json.loads(cleaned)
    if not isinstance(data, dict):
        msg = "Model response is not a valid JSON dictionary."
        raise ValueError(msg)

    decision = str(data.get("decision", "ask")).strip().lower()
    if decision not in ("allow", "soft_deny", "ask", "hard_deny", "deny"):
        decision = "ask"

    reason = str(data.get("reason", "Automated classification verdict.")).strip()
    risk_category = str(data.get("risk_category", "unknown")).strip()
    try:
        confidence = float(data.get("confidence", 1.0))
    except (ValueError, TypeError):
        confidence = 1.0

    return {
        "decision": decision,
        "reason": reason,
        "risk_category": risk_category,
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _call_google_api(
    raw_prompt: str,
    model: str,
    endpoint_url: str | None,
    api_key: str | None,
    timeout_secs: float,
) -> dict[str, Any]:
    key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key and not endpoint_url:
        msg = "GEMINI_API_KEY / GOOGLE_API_KEY is not configured in environment or config."
        raise ValueError(msg)

    if endpoint_url:
        url = endpoint_url
        headers = {"Content-Type": "application/json"}
        if key:
            headers["x-goog-api-key"] = key
    else:
        url = GOOGLE_ENDPOINT_TEMPLATE.format(model=model, key=key or "")
        headers = {"Content-Type": "application/json"}

    request_body = {
        "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
        "contents": [{"role": "user", "parts": [{"text": raw_prompt}]}],
        "generationConfig": {
            "response_mime_type": "application/json",
            "temperature": 0.0,
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(request_body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
        response_json = json.loads(resp.read().decode("utf-8"))
        candidates = response_json.get("candidates", [])
        if not candidates:
            msg = "No candidates returned from Google Gemini API."
            raise ValueError(msg)
        content_parts = candidates[0].get("content", {}).get("parts", [])
        if not content_parts:
            msg = "Empty content parts in Google Gemini response."
            raise ValueError(msg)
        raw_text = content_parts[0].get("text", "{}")
        return _parse_decision_text(raw_text)


def _call_openai_api(
    raw_prompt: str,
    model: str,
    endpoint_url: str | None,
    api_key: str | None,
    timeout_secs: float,
) -> dict[str, Any]:
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key and endpoint_url and "googleapis.com" in endpoint_url:
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    url = endpoint_url or OPENAI_DEFAULT_ENDPOINT
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    request_body = {
        "model": model or "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": raw_prompt},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(request_body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
        response_json = json.loads(resp.read().decode("utf-8"))
        choices = response_json.get("choices", [])
        if not choices:
            msg = "No choices returned from OpenAI wire endpoint."
            raise ValueError(msg)
        msg_obj = choices[0].get("message", {})
        raw_text = msg_obj.get("content", "{}")
        return _parse_decision_text(raw_text)


def _call_anthropic_api(
    raw_prompt: str,
    model: str,
    endpoint_url: str | None,
    api_key: str | None,
    timeout_secs: float,
) -> dict[str, Any]:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key and not endpoint_url:
        msg = "ANTHROPIC_API_KEY is not configured in environment or config."
        raise ValueError(msg)

    url = endpoint_url or ANTHROPIC_DEFAULT_ENDPOINT
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    if key:
        headers["x-api-key"] = key

    request_body = {
        "model": model or "claude-3-5-haiku-20241022",
        "system": SYSTEM_INSTRUCTION,
        "messages": [
            {
                "role": "user",
                "content": f"{raw_prompt}\n\nRespond with valid JSON adhering to schema only.",
            }
        ],
        "temperature": 0.0,
        "max_tokens": 1000,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(request_body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
        response_json = json.loads(resp.read().decode("utf-8"))
        content = response_json.get("content", [])
        if not content:
            msg = "No content returned from Anthropic API."
            raise ValueError(msg)
        raw_text = content[0].get("text", "{}")
        return _parse_decision_text(raw_text)


def classify_tool_call(
    workspace_paths: list[str],
    prior_prompts: list[str],
    active_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    tool_action: str | None = None,
    tool_summary: str | None = None,
    custom_guidelines: list[str] | None = None,
    provider: str = DEFAULT_PROVIDER,
    model: str = DEFAULT_MODEL,
    endpoint_url: str | None = None,
    api_key: str | None = None,
    timeout_secs: float = 4.0,
) -> tuple[str, dict[str, Any], str | None, float]:
    """
    Invokes the security classifier using the specified provider ('google', 'openai', 'anthropic').
    Uses only standard library urllib with zero external dependencies.
    Returns: (raw_prompt, classification_dict, error_msg, latency_ms)
    """
    raw_prompt = format_classifier_payload(
        workspace_paths=workspace_paths,
        prior_prompts=prior_prompts,
        active_prompt=active_prompt,
        tool_name=tool_name,
        tool_args=tool_args,
        tool_action=tool_action,
        tool_summary=tool_summary,
        custom_guidelines=custom_guidelines,
    )

    norm_provider = (provider or DEFAULT_PROVIDER).lower()
    if norm_provider == "gemini":
        norm_provider = "google"
    elif norm_provider == "claude":
        norm_provider = "anthropic"

    env_timeout = os.environ.get("AUTO_PERMISSIONS_TIMEOUT")
    if env_timeout:
        with contextlib.suppress(ValueError, TypeError):
            timeout_secs = float(env_timeout)

    start_time = time.perf_counter()
    try:
        if norm_provider == "openai":
            classification = _call_openai_api(
                raw_prompt=raw_prompt,
                model=model,
                endpoint_url=endpoint_url,
                api_key=api_key,
                timeout_secs=timeout_secs,
            )
        elif norm_provider == "anthropic":
            classification = _call_anthropic_api(
                raw_prompt=raw_prompt,
                model=model,
                endpoint_url=endpoint_url,
                api_key=api_key,
                timeout_secs=timeout_secs,
            )
        else:
            classification = _call_google_api(
                raw_prompt=raw_prompt,
                model=model,
                endpoint_url=endpoint_url,
                api_key=api_key,
                timeout_secs=timeout_secs,
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return raw_prompt, classification, None, elapsed_ms

    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        fallback = {
            "decision": "ask",
            "reason": f"Classifier fallback on error ({norm_provider}): {exc}",
            "risk_category": "classifier_error",
            "confidence": 0.0,
        }
        return raw_prompt, fallback, str(exc), elapsed_ms
