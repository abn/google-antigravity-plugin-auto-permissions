#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from hooks.transcript_parser import (
    extract_user_content,
    get_last_user_step_index,
    read_user_prompts_from_transcript,
)


class TestTranscriptParser(unittest.TestCase):
    def test_get_last_user_step_index(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as f:
            lines = [
                {"type": "USER_INPUT", "step_index": 1, "content": "Turn 1"},
                {"type": "PLANNER_RESPONSE", "step_index": 2, "content": "Working"},
                {"type": "USER_INPUT", "step_index": 15, "content": "Turn 2"},
                {"type": "PLANNER_RESPONSE", "step_index": 16, "content": "Working 2"},
            ]
            for line in lines:
                f.write(json.dumps(line) + "\n")
            temp_path = f.name

        try:
            self.assertEqual(get_last_user_step_index(temp_path), 15)
            self.assertIsNone(get_last_user_step_index("/non/existent/path"))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

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

    def test_extract_user_content_sanitization(self):
        # Step with XML envelope metadata
        raw_xml = (
            "<USER_REQUEST>\n"
            "Build the project and run pytest\n"
            "</USER_REQUEST>\n"
            "<ADDITIONAL_METADATA>\n"
            "The current local time is: 2026-08-15T04:10:26+02:00.\n"
            "</ADDITIONAL_METADATA>"
        )
        step = {"type": "USER_INPUT", "content": raw_xml}
        extracted = extract_user_content(step)
        self.assertEqual(extracted, "Build the project and run pytest")

        # Step with nested classifier payload envelopes
        nested_xml = (
            "<USER_REQUEST>\n"
            "<workspace_roots>\n"
            '["/workspace/project"]\n'
            "</workspace_roots>\n\n"
            "<active_user_prompt>\n"
            "<USER_REQUEST>\n"
            "<active_user_prompt>\n"
            "why are we using MODEL_PLACEHOLDER_M298?\n"
            "</active_user_prompt>\n"
            "</USER_REQUEST>\n"
            "</active_user_prompt>\n"
            "</USER_REQUEST>"
        )
        step_nested = {"type": "USER_INPUT", "content": nested_xml}
        self.assertEqual(
            extract_user_content(step_nested),
            "why are we using MODEL_PLACEHOLDER_M298?",
        )

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
            self.assertEqual(
                prior, ["[Turn 0]: Turn 1: Setup project", "[Turn 1]: Turn 2: Fix bug in auth"]
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_read_user_prompts_turn0_preservation(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as f:
            lines = [
                {"type": "USER_INPUT", "content": "Turn 0: Push changes as you go to origin"},
                {"type": "USER_INPUT", "content": "Turn 1: Add login page"},
                {"type": "USER_INPUT", "content": "Turn 2: Fix styling"},
                {"type": "USER_INPUT", "content": "Turn 3: Update colors"},
                {"type": "USER_INPUT", "content": "Turn 4: Fix responsive layout"},
                {"type": "USER_INPUT", "content": "Turn 5: Update tests"},
                {"type": "USER_INPUT", "content": "Turn 6: Final check"},
            ]
            for step_record in lines:
                f.write(json.dumps(step_record) + "\n")
            temp_path = f.name

        try:
            # max_history = 3, so prior prompts should contain Turn 0 + rolling Turns 3, 4, 5
            prior, active = read_user_prompts_from_transcript(temp_path, max_history=3)
            self.assertEqual(active, "Turn 6: Final check")
            self.assertEqual(
                prior,
                [
                    "[Turn 0]: Turn 0: Push changes as you go to origin",
                    "[Turn 3]: Turn 3: Update colors",
                    "[Turn 4]: Turn 4: Fix responsive layout",
                    "[Turn 5]: Turn 5: Update tests",
                ],
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
