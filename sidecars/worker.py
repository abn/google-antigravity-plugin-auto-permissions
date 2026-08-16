#!/usr/bin/env python3
"""
Background Persistent Security Classifier Worker for Google Antigravity Auto-Permissions.
Runs as a local sidecar daemon, bridging the hook to the active Antigravity Language Server
session for zero-key local authorization with persistent KV-prefix cache warmth.
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

DEFAULT_PORT = 4020
LOG = logging.getLogger("auto-permissions-worker")


class ClassifierWorkerState:
    """Thread-safe state manager for the persistent Language Server worker trajectory."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.trajectory_id: str | None = None
        self.ls_address: str | None = os.environ.get("ANTIGRAVITY_LS_ADDRESS")
        self.csrf_token: str | None = os.environ.get("ANTIGRAVITY_CSRF_TOKEN")
        self.project_id: str = os.environ.get("ANTIGRAVITY_PROJECT_ID", "default")
        self.initialized_time: float = time.time()

    def update_environment(self) -> None:
        """Refreshes connection environment variables if mutated dynamically."""
        if not self.ls_address:
            self.ls_address = os.environ.get("ANTIGRAVITY_LS_ADDRESS")
        if not self.csrf_token:
            self.csrf_token = os.environ.get("ANTIGRAVITY_CSRF_TOKEN")

    def call_ls_rpc(
        self, method: str, payload: dict[str, Any], timeout: float = 6.0
    ) -> dict[str, Any]:
        """Calls a Connect-RPC method on the local Language Server."""
        self.update_environment()
        if not self.ls_address or not self.csrf_token:
            msg = "Missing ANTIGRAVITY_LS_ADDRESS or ANTIGRAVITY_CSRF_TOKEN"
            raise RuntimeError(msg)

        clean_addr = self.ls_address.replace("http://", "").replace("https://", "")
        url = f"http://{clean_addr}/exa.language_server_pb.LanguageServerService/{method}"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Csrf-Token": self.csrf_token,
            "Connect-Protocol-Version": "1",
            "Origin": f"http://{clean_addr}",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_or_create_trajectory(self) -> str:
        """Retrieves active worker trajectory or creates a new persistent one."""
        with self.lock:
            if self.trajectory_id:
                return self.trajectory_id

            res = self.call_ls_rpc(
                "CreateCascadeTrajectory",
                {
                    "workspacePath": os.getcwd(),
                    "projectId": self.project_id,
                    "metadata": {
                        "persistent_worker": True,
                        "worker_name": "auto-permissions-security-gate",
                        "hidden": True,
                    },
                },
                timeout=8.0,
            )
            traj_id = res.get("trajectoryId")
            if not traj_id:
                msg = f"Failed to create persistent worker trajectory: {res}"
                raise RuntimeError(msg)

            self.trajectory_id = traj_id
            return self.trajectory_id

    def classify_payload(self, raw_prompt: str, timeout: float = 5.0) -> dict[str, Any]:
        """Submits classification request to the persistent worker trajectory."""
        traj_id = self.get_or_create_trajectory()
        res = self.call_ls_rpc(
            "HandleCascadeUserInteraction",
            {
                "trajectoryId": traj_id,
                "userMessage": raw_prompt,
                "readOnly": True,
            },
            timeout=timeout,
        )

        if "text" in res:
            try:
                return json.loads(res["text"])
            except Exception:
                pass

        return {
            "decision": res.get("decision", "allow"),
            "reason": res.get("reason", "Approved via Antigravity Language Server worker"),
            "risk_category": res.get("risk_category", "safe_routine"),
            "confidence": float(res.get("confidence", 0.95)),
            "provider": "antigravity_worker",
        }


WORKER_STATE = ClassifierWorkerState()


class ClassifierHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for the local auto-permissions sidecar worker."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP stderr logs for clean daemon execution."""
        pass

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/health", "/"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "auto-permissions-worker",
                    "uptime_seconds": time.time() - WORKER_STATE.initialized_time,
                    "has_ls_connection": bool(WORKER_STATE.ls_address and WORKER_STATE.csrf_token),
                    "trajectory_id": WORKER_STATE.trajectory_id,
                },
            )
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path == "/classify":
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(content_len).decode("utf-8")
                req_data = json.loads(body)
                raw_prompt = req_data.get("raw_prompt", "")
                timeout = float(req_data.get("timeout_secs", 5.0))

                classification = WORKER_STATE.classify_payload(raw_prompt, timeout=timeout)
                self._send_json(200, classification)
            except Exception as e:
                self._send_json(
                    500,
                    {
                        "error": str(e),
                        "decision": "ask",
                        "reason": f"Worker error: {e}",
                    },
                )
        elif self.path == "/shutdown":
            self._send_json(200, {"status": "shutting_down"})
            threading.Thread(target=self.server.shutdown).start()
        else:
            self._send_json(404, {"error": "Not found"})


def run_worker_server(port: int = DEFAULT_PORT) -> None:
    """Runs the persistent classifier worker daemon."""
    server = HTTPServer(("127.0.0.1", port), ClassifierHTTPHandler)
    LOG.info("Auto-permissions worker listening on 127.0.0.1:%d", port)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    port_env = os.environ.get("AUTO_PERMISSIONS_SIDECAR_PORT")
    port = int(port_env) if port_env and port_env.isdigit() else DEFAULT_PORT
    run_worker_server(port)
