"""Unit tests for Codex Hooks in AgentGuard."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
CODEX_HOOKS_DIR = TESTS_DIR.parent
PROJECT_ROOT = CODEX_HOOKS_DIR.parent
PYTHON = sys.executable

PRE_TOOL_SCRIPT = CODEX_HOOKS_DIR / "pre_tool_use.py"
POST_TOOL_SCRIPT = CODEX_HOOKS_DIR / "post_tool_use.py"
UNIFIED_HOOK = CODEX_HOOKS_DIR / "hook.py"


class CodexHooksTests(unittest.TestCase):
    def run_hook(self, script_path: Path, payload: dict | str) -> tuple[int, str, str]:
        raw_input = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        proc = subprocess.run(
            [PYTHON, str(script_path)],
            input=raw_input,
            text=True,
            capture_output=True,
            cwd=str(PROJECT_ROOT),
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    def test_benign_command_is_allowed(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_1",
            "turn_id": "turn_1",
            "tool_use_id": "tool_1",
            "tool_name": "bash",
            "tool_input": {"command": "python --version"},
            "cwd": str(PROJECT_ROOT),
        }
        code, stdout, _ = self.run_hook(PRE_TOOL_SCRIPT, payload)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "")

    def test_destructive_command_is_denied(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_2",
            "turn_id": "turn_1",
            "tool_use_id": "tool_2",
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(PROJECT_ROOT),
        }
        code, stdout, _ = self.run_hook(PRE_TOOL_SCRIPT, payload)
        self.assertEqual(code, 0)
        resp = json.loads(stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("destructive", resp["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_sensitive_credentials_access_is_denied(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_3",
            "turn_id": "turn_1",
            "tool_use_id": "tool_3",
            "tool_name": "view",
            "tool_input": {"file_path": "/root/.ssh/id_rsa"},
            "cwd": str(PROJECT_ROOT),
        }
        code, stdout, _ = self.run_hook(PRE_TOOL_SCRIPT, payload)
        self.assertEqual(code, 0)
        resp = json.loads(stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("sensitive", resp["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_tamper_attempt_on_policy_is_denied(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_4",
            "turn_id": "turn_1",
            "tool_use_id": "tool_4",
            "tool_name": "write",
            "tool_input": {"file_path": "policy.json", "content": "{}"},
            "cwd": str(PROJECT_ROOT),
        }
        code, stdout, _ = self.run_hook(PRE_TOOL_SCRIPT, payload)
        self.assertEqual(code, 0)
        resp = json.loads(stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("tamper", resp["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_post_tool_use_records_audit(self):
        payload = {
            "hook_event_name": "PostToolUse",
            "session_id": "sess_post",
            "turn_id": "turn_post",
            "tool_use_id": "tool_post",
            "tool_name": "bash",
            "cwd": str(PROJECT_ROOT),
        }
        code, stdout, _ = self.run_hook(POST_TOOL_SCRIPT, payload)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "")
        audit_file = CODEX_HOOKS_DIR / "logs" / "audit.jsonl"
        self.assertTrue(audit_file.exists())
        with audit_file.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertTrue(any("sess_post" in line for line in lines))

    def test_unified_hook_dispatch_pre_and_post(self):
        pre_payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "unified_sess",
            "turn_id": "t1",
            "tool_use_id": "u1",
            "tool_name": "bash",
            "tool_input": {"command": "echo test"},
        }
        code, stdout, _ = self.run_hook(UNIFIED_HOOK, pre_payload)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "")

        deny_payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "unified_sess",
            "turn_id": "t1",
            "tool_use_id": "u2",
            "tool_name": "bash",
            "tool_input": {"command": "shutdown -h now"},
        }
        code, stdout, _ = self.run_hook(UNIFIED_HOOK, deny_payload)
        self.assertEqual(code, 0)
        resp = json.loads(stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_invalid_json_fails_closed(self):
        code, stdout, _ = self.run_hook(PRE_TOOL_SCRIPT, "this-is-not-json")
        self.assertEqual(code, 0)
        resp = json.loads(stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
