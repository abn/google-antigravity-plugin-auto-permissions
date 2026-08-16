#!/usr/bin/env python3
"""
Unit tests for the Auto-Permissions Sidecar Worker daemon.
"""

import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from unittest.mock import patch

import pytest
from sidecars.worker import WORKER_STATE, ClassifierHTTPHandler, ClassifierWorkerState


class TestSidecarWorker:
    @pytest.fixture
    def mock_server(self):
        """Starts a mock test server on an ephemeral port."""
        server = HTTPServer(("127.0.0.1", 0), ClassifierHTTPHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        yield port
        server.shutdown()
        server.server_close()

    def test_worker_state_initialization(self):
        state = ClassifierWorkerState()
        assert state.trajectory_id is None
        assert state.project_id is not None

    def test_health_endpoint(self, mock_server):
        url = f"http://127.0.0.1:{mock_server}/health"
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["service"] == "auto-permissions-worker"

    def test_classify_endpoint_success(self, mock_server):
        url = f"http://127.0.0.1:{mock_server}/classify"
        mock_verdict = {
            "decision": "allow",
            "reason": "Safe test command matching user prompt",
            "risk_category": "safe_routine",
            "confidence": 0.98,
        }

        with patch.object(WORKER_STATE, "classify_payload", return_value=mock_verdict):
            req_data = json.dumps(
                {"raw_prompt": "<test>prompt</test>", "timeout_secs": 2.0}
            ).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["decision"] == "allow"
                assert data["confidence"] == 0.98

    def test_classify_endpoint_error_handling(self, mock_server):
        url = f"http://127.0.0.1:{mock_server}/classify"
        with patch.object(
            WORKER_STATE,
            "classify_payload",
            side_effect=RuntimeError("RPC connection refused"),
        ):
            req_data = json.dumps({"raw_prompt": "<test>prompt</test>"}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=3.0)
                pytest.fail("Expected HTTP 500 on worker exception")
            except urllib.error.HTTPError as e:
                assert e.code == 500
                body = json.loads(e.read().decode("utf-8"))
                assert body["decision"] == "ask"
                assert "RPC connection refused" in body["reason"]

    def test_shutdown_endpoint(self, mock_server):
        url = f"http://127.0.0.1:{mock_server}/shutdown"
        req = urllib.request.Request(
            url,
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "shutting_down"
