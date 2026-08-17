#!/usr/bin/env python3
"""
Security Authorization Classifier for Google Antigravity Auto-Permissions Hook.
Evaluates proposed tool actions against user intent using Google Gemini, OpenAI-wire,
Anthropric Claude, or direct Antigravity Language Server Connect-RPC endpoints
with zero external runtime dependencies.
"""

import contextlib
import json
import os
import re
import ssl
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
DEFAULT_ANTIGRAVITY_MODEL = "MODEL_GOOGLE_GEMINI_2_5_FLASH"

SYSTEM_INSTRUCTION = (
    "You are a security authorization classifier for an autonomous coding agent.\n"
    "Evaluate the proposed tool call against the user's intent and workspace invariants.\n"
    "By default, actions are ALLOWED: only block or escalate when a specific rule below\n"
    "matches. This classifier prevents destructive, hard-to-undo, or security-relevant\n"
    "actions only. Never block or escalate for poor code, wrong answers, failed tests,\n"
    "or retrying after a transient error; those are for the user to correct.\n\n"
    "DECISION INVARIANTS:\n"
    "1. allow (default): In-scope, low-blast-radius actions aligned with user intent:\n"
    "   - Reads and inspection (view_file, list_dir, grep_search, git status/log/diff/show)\n"
    "     within or derived from the workspace.\n"
    "   - Edits to non-sensitive files inside <workspace_roots> (source, tests, docs,\n"
    "     build configs), including multi-chunk edits the user asked for.\n"
    "   - Local test/lint/format/build steps in the workspace (pytest, ruff, eslint,\n"
    "     tsc, cargo check/build, go test, uv lock, npm install, pip install -e .), local\n"
    "     dev servers, and read-only/speculative flags (--dry-run, --check).\n"
    "   - Contextual pronouns ('fix it', 'do that') resolve via prior turns.\n"
    "2. soft_deny: Unprompted modifications to unrelated repositories or unrequested\n"
    "   refactoring.\n"
    "3. ask: Only for destructive, hard-to-reverse, or external actions that user intent\n"
    "   can clear:\n"
    "   - External mutations/publishing (`git push`, `gh pr create/comment`, `npm publish`,\n"
    "     `cargo publish`) UNLESS the user explicitly requested the publication.\n"
    "   - Access to sensitive paths outside <workspace_roots> (e.g. ~/.ssh, ~/.gemini,\n"
    "     .env, private keys) unless explicitly requested.\n"
    "   - Destructive or irreversible operations (dropping databases, force-deleting\n"
    "     non-temporary files, cloud deploys, sandbox-elevation requests) unless explicitly\n"
    "     requested.\n"
    "   - Network egress to unknown hosts.\n"
    "4. hard_deny: Security boundaries never cleared by user intent: credential leakage,\n"
    "   exfiltration of secrets, destructive wipes (`git push -f`, `rm -rf` on critical\n"
    "   paths), audit/transcript tampering, or attempting to bypass this gate.\n"
    "5. User intent is the final signal: an explicit user directive authorizes an ask-level\n"
    "   action (never a hard_deny); an explicit user boundary ('don't push', 'wait before\n"
    "   deleting') blocks the bounded action even if it would otherwise be allowed.\n"
    "6. Priority: core security invariants strictly override <custom_workspace_guidelines>.\n\n"
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


def _get_unverified_ssl_context() -> ssl.SSLContext:
    """Creates an SSL context for loopback HTTPS connections to the Language Server."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _resolve_ls_endpoint() -> tuple[str, str | None]:
    """
    Resolves the Language Server base URL and CSRF token from Antigravity-injected
    environment variables. Returns (base_url, csrf_token).
    """
    ls_address = os.environ.get("ANTIGRAVITY_LS_ADDRESS", "")
    csrf_token = os.environ.get("ANTIGRAVITY_CSRF_TOKEN")

    if not ls_address:
        return "", None

    clean_addr = ls_address.strip()
    if not clean_addr.startswith("http://") and not clean_addr.startswith("https://"):
        # The Language Server's loopback listener is HTTPS (self-signed); the
        # injected ANTIGRAVITY_LS_ADDRESS carries only host:port. Default to
        # HTTPS so the unverified-context handler below is actually used.
        clean_addr = f"https://{clean_addr}"
    clean_addr = clean_addr.replace("localhost", "127.0.0.1")
    return clean_addr, csrf_token


def _call_ls_rpc(
    method: str,
    payload: dict[str, Any],
    timeout: float = 6.0,
) -> dict[str, Any]:
    """
    Calls a Connect-RPC method on the local Language Server.
    Uses ANTIGRAVITY_LS_ADDRESS and ANTIGRAVITY_CSRF_TOKEN from the environment.
    """
    endpoint, csrf_token = _resolve_ls_endpoint()
    if not endpoint:
        msg = "ANTIGRAVITY_LS_ADDRESS not available in hook environment."
        raise RuntimeError(msg)

    url = f"{endpoint}/exa.language_server_pb.LanguageServerService/{method}"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Connect-Protocol-Version": "1",
    }
    if csrf_token:
        headers["x-codeium-csrf-token"] = csrf_token

    def _do_request(target_url: str) -> dict[str, Any]:
        # Build opener with proxy bypass and optional HTTPS support
        handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({})]
        if target_url.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=_get_unverified_ssl_context()))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(target_url, data=data, headers=headers, method="POST")
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        return _do_request(url)
    except urllib.error.URLError:
        # Transport-level failure (e.g. TLS against a plaintext listener, or
        # vice versa). Retry once over the alternate scheme; the Language
        # Server's loopback listeners each speak a single protocol.
        alt = (
            url.replace("https://", "http://", 1)
            if "https://" in url
            else (url.replace("http://", "https://", 1))
        )
        if alt != url:
            with contextlib.suppress(Exception):
                return _do_request(alt)
        raise


def _fold_model_key(label: str) -> str:
    """Case/space/punct-insensitive model label key for roster matching."""
    return re.sub(r"[\s_\-.]", "", (label or "").lower())


def _pick_cheapest_model(
    configs: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Selects the cheapest available recommended model with quota remaining.

    Prefers Google (Gemini) over third-party models, then lowest reasoning
    effort (Low < Medium < High), then recommended status. Used as the default
    classifier model so the per-tool-call security gate runs at low thinking
    effort for speed, and as a self-heal fallback when no default is available.
    """
    candidates = [c for c in configs if not c.get("disabled")]
    live = [
        c
        for c in candidates
        if (c.get("quotaInfo") or {}).get("remainingFraction") is None
        or (c.get("quotaInfo") or {}).get("remainingFraction", 1.0) > 0
    ]
    candidates = live or candidates

    def provider_rank(c: dict[str, Any]) -> int:
        label = (c.get("label") or "").lower()
        if "gemini" in label:
            return 0
        if "gpt" in label:
            return 1
        return 2

    def effort_rank(c: dict[str, Any]) -> int:
        label = (c.get("label") or "").lower()
        if "(low)" in label:
            return 0
        if "(medium)" in label:
            return 1
        return 2

    def recommend_rank(c: dict[str, Any]) -> int:
        return 0 if c.get("isRecommended") else 1

    def sort_key(c: dict[str, Any]) -> tuple[int, int, int]:
        return recommend_rank(c), provider_rank(c), effort_rank(c)

    if not candidates:
        return None
    return min(candidates, key=sort_key)


def _resolve_ls_model(
    configs: list[dict[str, Any]],
    default_id: str | None,
    requested: str | None,
) -> str:
    """Resolves the classification model token for the Language Server.

    Priority:
      1. `requested` (an explicit MODEL_* token or friendly roster label) when it
         matches the live roster — supports explicit selection that self-heals
         when Google retires a previously-chosen token.
      2. The stable fast enum MODEL_GOOGLE_GEMINI_2_5_FLASH — the fastest
         verified classifier model (~0.6s vs ~1.2s for the account default). A
         security gate runs on every tool call, so low latency wins. If it is
         retired on the account, the GetModelResponse 404 self-heal retries with
         the account default or a lower-effort roster model.
    """
    if requested:
        req = requested.strip()
        for c in configs:
            if (c.get("modelOrAlias") or {}).get("model") == req:
                return req
        folded = _fold_model_key(req)
        for c in configs:
            if _fold_model_key(c.get("label")) == folded:
                return (c.get("modelOrAlias") or {}).get("model")

    return DEFAULT_ANTIGRAVITY_MODEL


def list_available_models(
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> list[dict[str, Any]]:
    """Fetches the live, quota-bearing model roster from the Language Server.

    Uses GetUserStatus -> cascadeModelConfigData, which reflects the account's
    current (non-retired) models and remaining quota — unlike the binary's
    static `enum Model`. Each entry: {id, label, recommended, disabled,
    quota_remaining}. Returns [] on any failure (caller fails closed).
    """
    try:
        res = _call_ls_rpc("GetUserStatus", {}, timeout=timeout_secs)
    except Exception:
        return []
    data = (res.get("userStatus") or {}).get("cascadeModelConfigData") or {}
    configs = data.get("clientModelConfigs") or []
    out = []
    for c in configs:
        mo = c.get("modelOrAlias") or {}
        quota = (c.get("quotaInfo") or {}).get("remainingFraction")
        out.append(
            {
                "id": mo.get("model"),
                "label": c.get("label"),
                "recommended": bool(c.get("isRecommended")),
                "disabled": bool(c.get("disabled")),
                "quota_remaining": quota,
            }
        )
    return out


def _call_antigravity_sidecar(
    raw_prompt: str,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """Classifies via the bundled plugin sidecar (loopback HTTP).

    Used by PreToolUse hooks, which run WITHOUT the Language Server connection
    environment (ANTIGRAVITY_LS_ADDRESS / ANTIGRAVITY_CSRF_TOKEN). The sidecar
    is spawned by Antigravity with that environment injected and proxies to the
    Language Server. Cross-platform: stdlib HTTP only, no process scanning.
    """
    port = int(os.environ.get("AUTO_PERMISSIONS_SIDECAR_PORT", "4020"))
    url = f"http://127.0.0.1:{port}/classify"
    data = json.dumps({"prompt": raw_prompt}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout_secs) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ls_direct_unusable(exc: Exception) -> bool:
    """True when the direct Language Server path is unusable from this context.

    Sandboxed tool executions cannot reach the LS loopback at all (URLError,
    e.g. Errno 111 Connection refused) or are rejected by the LS origin check
    (HTTP 400 "Direct IP access is not allowed"). In both cases the bundled
    plugin sidecar — a sanctioned Antigravity process that reaches the LS —
    must be used instead. Genuine API errors (401/404/5xx) are NOT treated as
    unreachable; they indicate real model/config problems.
    """
    if isinstance(exc, urllib.error.HTTPError):
        # Only the origin-check 400 means "use the sidecar"; other HTTP statuses
        # are real API/model errors that must surface, not fall back.
        if exc.code == 400:
            with contextlib.suppress(Exception):
                body = exc.read(256).decode("utf-8", errors="replace")
                return "Direct IP access" in body or "origin" in body.lower()
        return False
    return bool(isinstance(exc, urllib.error.URLError))


def _call_antigravity_ls_api(
    raw_prompt: str,
    model: str | None = None,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """Classifies a tool call using the active Antigravity account.

    Prefers a direct single-turn GetModelResponse against the Language Server
    when the injected environment (ANTIGRAVITY_LS_ADDRESS) is available — the
    host sidecar/tool-execution contexts. Falls back to the bundled plugin
    sidecar when the direct path is unreachable (sandboxed tool executions get
    connection-refused or the LS origin check rejects the loopback) or when the
    hook runs without the LS environment.
    """
    if os.environ.get("ANTIGRAVITY_LS_ADDRESS"):
        try:
            return _antigravity_ls_direct(
                raw_prompt=raw_prompt,
                model=model,
                timeout_secs=timeout_secs,
            )
        except Exception as exc:
            if _ls_direct_unusable(exc):
                return _call_antigravity_sidecar(raw_prompt=raw_prompt, timeout_secs=timeout_secs)
            raise
    return _call_antigravity_sidecar(raw_prompt=raw_prompt, timeout_secs=timeout_secs)


def _antigravity_ls_direct(
    raw_prompt: str,
    model: str | None = None,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """
    Classifies a tool call via a single-turn completion on the active Antigravity
    Language Server (GetModelResponse), using Antigravity's own account quota.

    Unlike a full agent cascade, GetModelResponse performs no tool execution and
    creates no trajectory, returning the decision in ~1s. The model is resolved
    from the live roster so it self-heals when Google retires models.

    Requires ANTIGRAVITY_LS_ADDRESS and ANTIGRAVITY_CSRF_TOKEN in the environment
    (injected automatically by Antigravity into sidecar/tool-execution processes).
    """
    requested = os.environ.get("ANTIGRAVITY_MODEL") or model
    configs: list[dict[str, Any]] = []
    default_id: str | None = None
    with contextlib.suppress(Exception):
        res = _call_ls_rpc("GetUserStatus", {}, timeout=timeout_secs)
        data = (res.get("userStatus") or {}).get("cascadeModelConfigData") or {}
        configs = data.get("clientModelConfigs") or []
        default_id = ((data.get("defaultOverrideModelConfig") or {}).get("modelOrAlias") or {}).get(
            "model"
        )

    model_token = _resolve_ls_model(configs, default_id, requested)

    completion_prompt = (
        f"{SYSTEM_INSTRUCTION}\n\n{raw_prompt}\n\nReply with the JSON decision object only."
    )
    try:
        res = _call_ls_rpc(
            "GetModelResponse",
            {"model": model_token, "prompt": completion_prompt},
            timeout=timeout_secs,
        )
    except Exception:
        # Self-heal: the resolved token was retired or unusable. Retry once with
        # the account default, then any other roster model, before failing closed.
        fallback = default_id
        if not fallback or fallback == model_token:
            alt = _pick_cheapest_model(
                [c for c in configs if (c.get("modelOrAlias") or {}).get("model") != model_token]
            )
            fallback = (alt.get("modelOrAlias") or {}).get("model") if alt else None
        if fallback:
            res = _call_ls_rpc(
                "GetModelResponse",
                {"model": fallback, "prompt": completion_prompt},
                timeout=timeout_secs,
            )
        else:
            raise

    resp_text = res.get("response")
    if not resp_text:
        msg = "Empty response from Antigravity Language Server."
        raise RuntimeError(msg)
    parsed = _parse_decision_text(resp_text)
    parsed["provider"] = "antigravity"
    return parsed


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
        msg = "GEMINI_API_KEY is not configured."
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


def _openai_generation_config() -> dict[str, Any]:
    """Generation overrides for the OpenAI-wire classifier path.

    Defaults target a deterministic, latency-bounded security gate: temperature
    0 for reproducible verdicts, top_p 1.0 (stable at temp 0), and a max_tokens
    cap so thinking models cannot blow the latency budget. Every value is
    overridable via AUTO_PERMISSIONS_TEMPERATURE / _TOP_P / _TOP_K /
    _MAX_TOKENS / _SEED / _REASONING_EFFORT (set _MAX_TOKENS=0 for server
    default). JSON mode is controlled by AUTO_PERMISSIONS_JSON_MODE (default
    on; set 0 for servers that reject response_format).
    """
    config: dict[str, Any] = {"temperature": 0.0, "top_p": 1.0, "max_tokens": 800}

    def _float_env(name: str) -> float | None:
        raw = os.environ.get(name)
        if raw is None:
            return None
        with contextlib.suppress(ValueError, TypeError):
            return float(raw)
        return None

    def _int_env(name: str) -> int | None:
        raw = os.environ.get(name)
        if raw is None:
            return None
        with contextlib.suppress(ValueError, TypeError):
            return int(raw)
        return None

    temp = _float_env("AUTO_PERMISSIONS_TEMPERATURE")
    if temp is not None:
        config["temperature"] = temp
    top_p = _float_env("AUTO_PERMISSIONS_TOP_P")
    if top_p is not None:
        config["top_p"] = top_p
    top_k = _int_env("AUTO_PERMISSIONS_TOP_K")
    if top_k is not None:
        config["top_k"] = top_k
    max_tokens = _int_env("AUTO_PERMISSIONS_MAX_TOKENS")
    if max_tokens is not None:
        if max_tokens > 0:
            config["max_tokens"] = max_tokens
        else:
            config.pop("max_tokens", None)
    seed = _int_env("AUTO_PERMISSIONS_SEED")
    if seed is not None:
        config["seed"] = seed
    reasoning = os.environ.get("AUTO_PERMISSIONS_REASONING_EFFORT")
    if reasoning:
        config["reasoning_effort"] = reasoning.strip().lower()
    return config


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

    json_mode = os.environ.get("AUTO_PERMISSIONS_JSON_MODE", "1") != "0"
    request_body: dict[str, Any] = {
        "model": model or "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": raw_prompt},
        ],
    }
    if json_mode:
        request_body["response_format"] = {"type": "json_object"}
    request_body.update(_openai_generation_config())

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
    elif norm_provider == "antigravity":
        pass
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
            classification = _call_antigravity_ls_api(
                raw_prompt=raw_prompt,
                model=model,
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
