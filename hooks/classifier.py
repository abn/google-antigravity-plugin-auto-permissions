#!/usr/bin/env python3
"""
Security Authorization Classifier for Google Antigravity Auto-Permissions Hook.
Evaluates proposed tool actions against user intent using Google Gemini, OpenAI-wire,
or Anthropic Claude endpoints with zero external runtime dependencies.
"""

import contextlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_PROVIDER = "google"
DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_TIMEOUT_SECS = 6.0
GOOGLE_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
)
OPENAI_DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"

SYSTEM_INSTRUCTION = (
    "You are a strict security authorization classifier for an autonomous coding agent.\n"
    "Classify if the proposed tool call aligns with user intent and workspace invariants.\n\n"
    "DECISION INVARIANTS:\n"
    "1. allow: Safe workspace read/write/test operations matching user intent. Contextual\n"
    "   pronouns ('fix it', 'do that') resolve via prior turns. Routine lifecycle support\n"
    "   (updating lockfiles via `uv lock`/`npm install`, running linters `ruff`/`eslint`,\n"
    "   local tests `pytest`, reading skill `SKILL.md`, or read-only/speculative flags like\n"
    "   `--dry-run`) MUST be classified as 'allow'.\n"
    "2. soft_deny: Unprompted modifications to unrelated repositories or unrequested refactoring.\n"
    "3. ask: Operations requiring human confirmation:\n"
    "   - External mutations/publishing (`git push`, `gh pr create/comment`, `npm publish`)\n"
    "     UNLESS the user explicitly requested to push/post/publish in their instructions.\n"
    "   - Access to paths outside <workspace_roots> (e.g. parent directories, ~/.ssh, ~/.gemini)\n"
    "     unless explicitly requested.\n"
    "   - Destructive operations (database migrations, deleting non-temporary files,\n"
    "     cloud deploys).\n"
    "4. hard_deny: Malicious actions (credential leakage, network exfiltration, destructive wipes\n"
    "   like `git push -f`, audit/transcript tampering).\n"
    "5. Priority: Core security invariants strictly override <custom_workspace_guidelines>.\n\n"
    "JSON RESPONSE SCHEMA:\n"
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
    session_goal: str | None = None,
) -> str:
    """
    Formats minimal sanitized context into structured XML for the security classifier.
    Follows strict volatility ordering (static top -> volatile bottom) and absolute
    chronological turn IDs to maximize provider prefix / KV-cache hit rates.
    """
    # 1. Workspace roots (Static throughout session, normalized & sorted)
    normalized_roots = sorted(list(dict.fromkeys(os.path.abspath(p) for p in workspace_paths)))
    roots_section = f"""<workspace_roots>
{json.dumps(normalized_roots)}
</workspace_roots>"""

    # 2. Custom guidelines (Static throughout session if configured)
    guidelines_section = ""
    if custom_guidelines:
        gl_lines = "\n".join(f"- {g.strip()}" for g in custom_guidelines if g.strip())
        if gl_lines:
            guidelines_section = f"""<custom_workspace_guidelines>
{gl_lines}
</custom_workspace_guidelines>"""

    # 3. Session goal / anchor (Static throughout session if configured)
    goal_section = ""
    if session_goal and session_goal.strip():
        goal_section = f"""<session_goal>
{session_goal.strip()}
</session_goal>"""

    # 4. Prior user prompts (Monotonically appended with absolute chronological turn labels)
    prior_section = ""
    if prior_prompts:
        lines = []
        for i, p in enumerate(prior_prompts):
            p_clean = p.strip()
            if p_clean.startswith("[Turn ") or p_clean.startswith("[Session Goal / Turn 0]"):
                lines.append(f"- {p_clean}")
            else:
                lines.append(f"- [Turn {i}]: {p_clean}")

        history_lines = "\n".join(lines)
        prior_section = f"""<prior_user_prompts>
{history_lines}
</prior_user_prompts>"""

    # 5. Active user prompt (Volatile per user turn)
    active_clean = (
        active_prompt.strip() if active_prompt else "(No explicit active prompt provided)"
    )
    active_section = f"""<active_user_prompt>
{active_clean}
</active_user_prompt>"""

    # 6. Proposed tool call (High-frequency evaluation payload with deterministic key order)
    tool_metadata = []
    if tool_summary:
        tool_metadata.append(f"Summary: {tool_summary.strip()}")
    if tool_action:
        tool_metadata.append(f"Action Intent: {tool_action.strip()}")
    metadata_block = ("\n" + "\n".join(tool_metadata)) if tool_metadata else ""

    tool_section = f"""<proposed_tool_call>
Tool: {tool_name}{metadata_block}
Arguments: {json.dumps(tool_args, indent=2, sort_keys=True)}
</proposed_tool_call>"""

    sections = [roots_section]
    if guidelines_section:
        sections.append(guidelines_section)
    if goal_section:
        sections.append(goal_section)
    if prior_section:
        sections.append(prior_section)
    sections.append(active_section)
    sections.append(tool_section)

    return "\n\n".join(sections)


def _clean_json_text(text: str) -> str:
    """Extracts valid JSON object from response, handling preambles, fences, commentary."""
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text

    # Markdown fence regex extraction (e.g. ```json\n{...}\n```)
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fence_match:
        return fence_match.group(1).strip()

    # Outer brace extraction fallback
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        return text[first_brace : last_brace + 1].strip()

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


def _probe_sidecar_health(port: int = 4020, timeout_secs: float = 0.2) -> bool:
    """Checks if the local sidecar worker is responsive on its /health endpoint."""
    url = f"http://127.0.0.1:{port}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "ok"
    except Exception:
        return False
    return False


def _resolve_sidecar_worker_script() -> str | None:
    """Resolves absolute path to sidecars/worker.py across relative and plugin paths."""
    candidates = [
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sidecars",
            "worker.py",
        ),
        os.path.expanduser("~/.gemini/config/plugins/auto-permissions/sidecars/worker.py"),
        os.path.expanduser("~/.config/antigravity/sidecars/worker.py"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _ensure_sidecar_running(port: int = 4020, max_wait_secs: float = 1.0) -> bool:
    """
    Ensures the persistent sidecar worker daemon is running on 127.0.0.1:port,
    auto-spawning it in the background if offline.
    """
    if _probe_sidecar_health(port=port, timeout_secs=0.15):
        return True

    worker_script = _resolve_sidecar_worker_script()
    if not worker_script:
        return False

    try:
        env = os.environ.copy()
        env["AUTO_PERMISSIONS_SIDECAR_PORT"] = str(port)
        subprocess.Popen(
            [sys.executable, worker_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    except Exception:
        return False

    # Poll /health until ready or timeout
    start_poll = time.perf_counter()
    while (time.perf_counter() - start_poll) < max_wait_secs:
        time.sleep(0.05)
        if _probe_sidecar_health(port=port, timeout_secs=0.15):
            return True

    return False


def _call_antigravity_sidecar_api(
    raw_prompt: str,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
    port: int | None = None,
) -> dict[str, Any]:
    """
    Queries the local persistent auto-permissions sidecar worker.
    Connects to 127.0.0.1:4020 (or AUTO_PERMISSIONS_SIDECAR_PORT) to leverage
    Antigravity's active Language Server session without an explicit API key.
    Auto-spawns the worker daemon in the background if offline.
    """
    effective_port = port or int(os.environ.get("AUTO_PERMISSIONS_SIDECAR_PORT", "4020"))
    _ensure_sidecar_running(port=effective_port, max_wait_secs=1.0)

    url = f"http://127.0.0.1:{effective_port}/classify"
    data = json.dumps({"raw_prompt": raw_prompt, "timeout_secs": timeout_secs}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _call_cloudcode_oauth_api(
    raw_prompt: str,
    oauth_token: str | None = None,
    project_id: str | None = None,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """
    Queries Google Cloud Code Assist API using active Google OAuth token.
    Leverages user's Antigravity / Cloud Code login quota with zero external API keys.
    """
    token = (
        oauth_token
        or os.environ.get("GOOGLE_OAUTH_TOKEN")
        or os.environ.get("CLOUDSDK_AUTH_ACCESS_TOKEN")
    )
    if not token:
        msg = "Missing Google OAuth token (GOOGLE_OAUTH_TOKEN / CLOUDSDK_AUTH_ACCESS_TOKEN)."
        raise ValueError(msg)

    proj = project_id or os.environ.get("ANTIGRAVITY_PROJECT_ID", "default")
    url = f"https://cloudaicompanion.googleapis.com/v1/projects/{proj}:generateChatCompletions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    request_body = {
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
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
            msg = "No candidates returned from Cloud Code Assist API."
            raise ValueError(msg)
        content_parts = candidates[0].get("content", {}).get("parts", [])
        if not content_parts:
            msg = "Empty content parts in Cloud Code response."
            raise ValueError(msg)
        raw_text = content_parts[0].get("text", "{}")
        return _parse_decision_text(raw_text)


def _call_google_api(
    raw_prompt: str,
    model: str,
    endpoint_url: str | None,
    api_key: str | None,
    timeout_secs: float,
) -> dict[str, Any]:
    key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key and not endpoint_url:
        # Zero-Key Fallback Tier 1: Check if local sidecar worker is active
        try:
            return _call_antigravity_sidecar_api(raw_prompt, timeout_secs=min(timeout_secs, 3.0))
        except Exception:
            pass

        # Zero-Key Fallback Tier 2: Check if Google OAuth token is present
        oauth_token = os.environ.get("GOOGLE_OAUTH_TOKEN") or os.environ.get(
            "CLOUDSDK_AUTH_ACCESS_TOKEN"
        )
        if oauth_token:
            return _call_cloudcode_oauth_api(
                raw_prompt, oauth_token=oauth_token, timeout_secs=timeout_secs
            )

        msg = (
            "GEMINI_API_KEY is not configured and local Antigravity sidecar worker "
            "is not running on 127.0.0.1:4020."
        )
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
        "system": [
            {
                "type": "text",
                "text": SYSTEM_INSTRUCTION,
                "cache_control": {"type": "ephemeral"},
            }
        ],
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


def _format_request_error(exc: Exception, timeout_secs: float = DEFAULT_TIMEOUT_SECS) -> str:
    """Extracts granular, sanitized HTTP error code and response payload snippet."""
    if isinstance(exc, urllib.error.HTTPError):
        body_snippet = ""
        with contextlib.suppress(Exception):
            raw_body = exc.read(512).decode("utf-8", errors="replace").strip()
            if raw_body:
                with contextlib.suppress(Exception):
                    err_json = json.loads(raw_body)
                    if isinstance(err_json, dict):
                        if "error" in err_json:
                            err_val = err_json["error"]
                            if isinstance(err_val, dict) and "message" in err_val:
                                body_snippet = str(err_val["message"])
                            elif isinstance(err_val, str):
                                body_snippet = err_val
                        elif "message" in err_json:
                            body_snippet = str(err_json["message"])
                if not body_snippet:
                    body_snippet = raw_body[:180].replace("\n", " ").strip()

        if body_snippet:
            return f"HTTP {exc.code} {exc.reason}: {body_snippet}"
        return f"HTTP {exc.code} {exc.reason}"

    if isinstance(exc, urllib.error.URLError):
        reason = str(exc.reason)
        return f"Network/Connection error: {reason}"
    if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
        return f"Request timed out (>{timeout_secs:.1f}s)"
    return str(exc)


def classify_tool_call(
    workspace_paths: list[str],
    prior_prompts: list[str],
    active_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    tool_action: str | None = None,
    tool_summary: str | None = None,
    custom_guidelines: list[str] | None = None,
    session_goal: str | None = None,
    provider: str = DEFAULT_PROVIDER,
    model: str = DEFAULT_MODEL,
    endpoint_url: str | None = None,
    api_key: str | None = None,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
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
        session_goal=session_goal,
    )

    norm_provider = (provider or DEFAULT_PROVIDER).lower()
    if norm_provider in ("gemini", "google"):
        norm_provider = "google"
    elif norm_provider in ("claude", "anthropic"):
        norm_provider = "anthropic"
    elif norm_provider in ("antigravity", "sidecar", "worker"):
        norm_provider = "antigravity"
    elif norm_provider in ("cloudcode", "oauth"):
        norm_provider = "cloudcode"

    env_timeout = os.environ.get("AUTO_PERMISSIONS_TIMEOUT") or os.environ.get(
        "AUTO_PERMISSIONS_TIMEOUT_SECS"
    )
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
        elif norm_provider == "antigravity":
            classification = _call_antigravity_sidecar_api(
                raw_prompt=raw_prompt,
                timeout_secs=timeout_secs,
            )
        elif norm_provider == "cloudcode":
            classification = _call_cloudcode_oauth_api(
                raw_prompt=raw_prompt,
                oauth_token=api_key,
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

        classification["provider"] = norm_provider
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return raw_prompt, classification, None, elapsed_ms

    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        err_msg = _format_request_error(exc, timeout_secs=timeout_secs)
        fallback = {
            "decision": "ask",
            "reason": f"Classifier fallback on error ({norm_provider}): {err_msg}",
            "risk_category": "classifier_error_fallback",
            "confidence": 0.0,
            "provider": norm_provider,
            "error": err_msg,
        }
        return raw_prompt, fallback, err_msg, elapsed_ms
