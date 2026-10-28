import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add claude_code_hooks folder to sys.path
HOOKS_DIR = Path(__file__).resolve().parents[1]
import sys

if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import hook


class ClaudeHookTests(unittest.TestCase):
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

    def test_normalize_pre_tool_event(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "test_s1",
            "cwd": "/workspace",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        event = hook.normalize(payload)
        self.assertEqual(event["agent_kind"], "claude_code")
        self.assertEqual(event["event"], "pre_tool")
        self.assertEqual(event["session_id"], "test_s1")
        self.assertEqual(event["tool_name"], "Bash")
        self.assertEqual(event["tool_input"], {"command": "ls -la"})

    def test_render_deny_verdict(self):
        decision = {"verdict": "deny", "reason": "Destructive command"}
        output_str = hook.render(decision)
        self.assertIsNotNone(output_str)
        data = json.loads(output_str)
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("Destructive command", data["hookSpecificOutput"]["permissionDecisionReason"])

    def test_render_ask_verdict(self):
        decision = {"verdict": "ask", "reason": "Requires confirmation"}
        output_str = hook.render(decision)
        self.assertIsNotNone(output_str)
        data = json.loads(output_str)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_render_silent_verdict(self):
        # Silent must return None (nothing printed to stdout, Claude Code proceeds normally)
        decision = {"verdict": "silent", "reason": ""}
        output_str = hook.render(decision)
        self.assertIsNone(output_str)

    def test_session_state_and_run_tag(self):
        event = {
            "event": "prompt_submit",
            "session_id": "sess_123",
            "prompt": "Build feature [run:exp-42]",
            "timestamp": "2026-10-28T10:00:00Z",
        }
        hook.update_session(event, max_task_chars=1000)
        state = hook.get_session_state("sess_123")
        self.assertIn("Build feature", state.get("task", ""))
        self.assertEqual(state.get("run_tag"), "exp-42")
        self.assertEqual(event.get("run_tag"), "exp-42")

    def test_validate_decision_rejects_allow(self):
        # The hook architecture deliberately rejects "allow"; only silent/ask/deny are allowed.
        with self.assertRaises(ValueError):
            hook.validate_decision({"verdict": "allow", "reason": ""})


if __name__ == "__main__":
    unittest.main()
