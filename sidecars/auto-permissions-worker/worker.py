#!/usr/bin/env python3
"""
Thin zero-key classification sidecar for the auto-permissions security gate.

Antigravity spawns this plugin sidecar and injects the Language Server
connection environment (ANTIGRAVITY_LS_ADDRESS, ANTIGRAVITY_CSRF_TOKEN, ...).
PreToolUse hooks run WITHOUT that environment, so the gate calls this worker
over loopback HTTP to classify tool calls via the Language Server's single-turn
GetModelResponse endpoint. Python standard library only.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

current_dir = os.path.dirname(os.path.abspath(__file__))
plugin_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

import hooks.classifier as classifier  # noqa: E402

HOST = "127.0.0.1"
PORT = int(os.environ.get("AUTO_PERMISSIONS_SIDECAR_PORT", "4020"))
TIMEOUT_SECS = 8.0


def classify(prompt: str) -> dict:
    """Classifies a raw prompt via the Language Server, failing closed."""
    try:
        result = classifier._call_antigravity_ls_api(
            raw_prompt=prompt,
            timeout_secs=TIMEOUT_SECS,
        )
        return result
    except Exception as exc:
        return {
            "decision": "ask",
            "reason": f"Classifier fallback (sidecar): {exc}",
            "risk_category": "classifier_error_fallback",
            "confidence": 0.0,
            "provider": "antigravity",
        }


class _Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/").endswith("/health"):
            self._send_json(
                200,
                {
                    "ok": True,
                    "ls_configured": bool(os.environ.get("ANTIGRAVITY_LS_ADDRESS")),
                    "model_count": len(classifier.list_available_models()),
                },
            )
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self.path.rstrip("/").endswith("/classify"):
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            prompt = payload.get("prompt", "")
        except Exception:
            self._send_json(400, {"error": "invalid JSON body"})
            return
        if not prompt:
            self._send_json(400, {"error": "prompt is required"})
            return
        self._send_json(200, classify(prompt))

    def log_message(self, *args) -> None:
        pass


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), _Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
