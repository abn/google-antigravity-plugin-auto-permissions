#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from hooks.transcript_parser import extract_user_content, read_user_prompts_from_transcript


class TestTranscriptParser(unittest.TestCase):
    def test_extract_user_content_types(self):
        # Step with type USER_INPUT and string content
        step1 = {"type": "USER_INPUT", "content": "Run the tests"}
        self.assertEqual(extract_user_content(step1), "Run the tests")

        # Step with source USER_EXPLICIT and list of parts
        step2 = {
            "source": "USER_EXPLICIT",
            "content": [{"text": "Part 1"}, {"text": "Part 2"}],
        }
        self.assertEqual(extract_user_content(step2), "Part 1\nPart 2")

        # Step from assistant model (should be ignored)
        step3 = {"type": "PLANNER_RESPONSE", "source": "MODEL", "content": "I will run pytest"}
        self.assertIsNone(extract_user_content(step3))

    def test_read_user_prompts_empty_or_missing(self):
        prior, active = read_user_prompts_from_transcript("/non/existent/path.jsonl")
        self.assertEqual(prior, [])
        self.assertIsNone(active)

    def test_read_user_prompts_multiturn(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as f:
            lines = [
                {"type": "USER_INPUT", "content": "Turn 1: Setup project"},
                {"type": "PLANNER_RESPONSE", "source": "MODEL", "content": "Setting up"},
                {"type": "USER_INPUT", "content": "Turn 2: Fix bug in auth"},
                {"type": "PLANNER_RESPONSE", "source": "MODEL", "content": "Fixing"},
                {"type": "USER_INPUT", "content": "Turn 3: Run the test suite"},
            ]
            for step_record in lines:
                f.write(json.dumps(step_record) + "\n")
            temp_path = f.name

        try:
            prior, active = read_user_prompts_from_transcript(temp_path, max_history=4)
            self.assertEqual(active, "Turn 3: Run the test suite")
            self.assertEqual(prior, ["Turn 1: Setup project", "Turn 2: Fix bug in auth"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
