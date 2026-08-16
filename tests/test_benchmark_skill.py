#!/usr/bin/env python3
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

script_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../skills/auto-permissions-benchmark/scripts/benchmark_accuracy.py",
    )
)
spec = importlib.util.spec_from_file_location("benchmark_accuracy", script_path)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class TestBenchmarkSkill(unittest.TestCase):
    def test_cases_are_well_formed(self):
        self.assertGreaterEqual(len(benchmark.CASES), 15)
        for prompt, tool, args, accepted, note in benchmark.CASES:
            self.assertIsInstance(prompt, str)
            self.assertIsInstance(tool, str)
            self.assertIsInstance(args, dict)
            self.assertIsInstance(accepted, list)
            self.assertTrue(accepted)
            self.assertIsInstance(note, str)
            self.assertIn(tool, ("run_command", "write_to_file", "view_file"))

    def test_run_case_returns_classifier_decision(self):
        with patch.object(benchmark, "classify_tool_call") as mock_cls:
            mock_cls.return_value = (
                "<raw>",
                {
                    "decision": "hard_deny",
                    "risk_category": "data_exfiltration_or_destruction",
                    "reason": "nope",
                },
                None,
                123.4,
            )
            got, latency, error = benchmark.run_case(
                prompt="Wipe the disk",
                tool="run_command",
                args={"CommandLine": "rm -rf /"},
                workspace_paths=["/tmp"],
                provider="antigravity",
                model=None,
                endpoint_url=None,
                api_key=None,
                api_key_env=None,
                timeout_secs=10.0,
            )
        self.assertEqual(got, "hard_deny")
        self.assertEqual(latency, 123.4)
        self.assertIsNone(error)

    def test_main_json_output(self):
        with patch.object(benchmark, "classify_tool_call") as mock_cls:
            mock_cls.return_value = (
                "<raw>",
                {
                    "decision": "allow",
                    "risk_category": "safe_routine",
                    "reason": "ok",
                },
                None,
                50.0,
            )
            with (
                patch("sys.argv", ["benchmark_accuracy.py", "--json", "--limit", "2"]),
                patch.object(benchmark, "print") as mock_print,
            ):
                code = benchmark.main()
        self.assertEqual(code, 0)
        payload = mock_print.call_args_list[0].args[0]
        data = json.loads(payload)
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["passed"], 2)
        self.assertEqual(data["accuracy"], 1.0)
        self.assertEqual(data["latency_ms"]["count"], 2)
        self.assertEqual(data["latency_ms"]["min"], 50.0)
        self.assertEqual(data["latency_ms"]["max"], 50.0)

    def test_latency_stats_aggregation(self):
        results = [
            {"error": None, "latency_ms": 400.0},
            {"error": None, "latency_ms": 200.0},
            {"error": None, "latency_ms": 600.0},
            {"error": "boom", "latency_ms": 900.0},  # excluded (error)
            {"error": None, "latency_ms": 0.0},  # excluded (non-positive)
        ]
        stats = benchmark._latency_stats(results)
        self.assertEqual(stats["count"], 3)
        self.assertEqual(stats["min"], 200.0)
        self.assertEqual(stats["median"], 400.0)
        self.assertEqual(stats["max"], 600.0)
        self.assertEqual(stats["mean"], 400.0)


if __name__ == "__main__":
    unittest.main()
