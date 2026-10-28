import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parents[1]
import sys

if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import hook


class AntigravityHookTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.orig_log_path = hook.log_path
        self.orig_state_dir = hook.state_dir
        self.test_log = os.path.join(self.temp_dir, "test_events.jsonl")
        self.test_state = os.path.join(self.temp_dir, "state")
        hook.log_path = lambda: self.test_log
        hook.state_dir = lambda: self.test_state

    def tearDown(self):
        hook.log_path = self.orig_log_path
        hook.state_dir = self.orig_state_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_and_normalize_pre_tool(self):
        payload = {
            "conversationId": "conv-12345",
            "stepIdx": 4,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "python --version"},
            },
            "workspacePaths": ["/workspace"],
        }
        event = hook.normalize(payload)
        self.assertEqual(event["agent_kind"], "antigravity_ide")
        self.assertEqual(event["event"], "pre_tool")
        self.assertEqual(event["session_id"], "conv-12345")
        self.assertEqual(event["tool_name"], "run_command")
        self.assertEqual(event["tool_input"], {"CommandLine": "python --version"})

    def test_detect_and_normalize_post_tool(self):
        payload = {
            "conversationId": "conv-12345",
            "stepIdx": 5,
            "toolCall": {"name": "run_command", "args": {}},
            "error": "command not found",
        }
        event = hook.normalize(payload)
        self.assertEqual(event["event"], "post_tool")
        self.assertEqual(event["error"], "command not found")

    def test_render_pre_tool_deny(self):
        decision = {"verdict": "deny", "reason": "Destructive command"}
        output_str = hook.render("pre_tool", decision)
        data = json.loads(output_str)
        self.assertEqual(data["decision"], "deny")
        self.assertIn("Destructive command", data["reason"])

    def test_render_pre_tool_ask(self):
        decision = {"verdict": "ask", "reason": "Needs approval"}
        output_str = hook.render("pre_tool", decision)
        data = json.loads(output_str)
        self.assertEqual(data["decision"], "ask")
        self.assertIn("Needs approval", data["reason"])

    def test_render_pre_tool_allow(self):
        decision = {"verdict": "silent", "reason": ""}
        output_str = hook.render("pre_tool", decision)
        data = json.loads(output_str)
        self.assertEqual(data["decision"], "allow")

    def test_render_post_tool_empty_object(self):
        output_str = hook.render("post_tool", None)
        self.assertEqual(json.loads(output_str), {})


if __name__ == "__main__":
    unittest.main()
