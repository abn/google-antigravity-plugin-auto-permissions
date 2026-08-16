#!/usr/bin/env python3
import importlib.util
import os
import unittest
from unittest.mock import patch

script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../sidecars/auto-permissions-worker/worker.py",
    )
)
spec = importlib.util.spec_from_file_location("auto_permissions_worker", script_path)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class TestSidecarWorker(unittest.TestCase):
    def test_classify_returns_classification(self):
        with patch.object(
            worker.classifier,
            "_call_antigravity_ls_api",
            return_value={"decision": "allow", "provider": "antigravity", "confidence": 0.99},
        ):
            result = worker.classify("the-prompt")
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["provider"], "antigravity")

    def test_classify_fails_closed_on_classifier_error(self):
        with patch.object(
            worker.classifier,
            "_call_antigravity_ls_api",
            side_effect=RuntimeError("LS unreachable"),
        ):
            result = worker.classify("the-prompt")
        self.assertEqual(result["decision"], "ask")
        self.assertIn("Classifier fallback (sidecar)", result["reason"])

    def test_classify_forwards_prompt(self):
        captured = {}

        def fake_ls_api(raw_prompt, timeout_secs=worker.TIMEOUT_SECS):
            captured["prompt"] = raw_prompt
            return {"decision": "allow", "provider": "antigravity"}

        with patch.object(worker.classifier, "_call_antigravity_ls_api", side_effect=fake_ls_api):
            worker.classify("forward-me")
        self.assertEqual(captured["prompt"], "forward-me")

    def test_port_env_override(self):
        # The hook and the sidecar share the same fixed default port; the env
        # var lets a user move it without touching the hook's fallback default.
        self.assertEqual(worker.PORT, int(os.environ.get("AUTO_PERMISSIONS_SIDECAR_PORT", "4020")))


if __name__ == "__main__":
    unittest.main()
