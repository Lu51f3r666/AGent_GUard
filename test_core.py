import json
import sys
import tempfile
import unittest
from pathlib import Path

AGENTGUARD = Path(__file__).resolve().parents[1] / ".codex" / "agentguard"
sys.path.insert(0, str(AGENTGUARD))

from core import evaluate_action, normalize_event  # noqa: E402


class AgentGuardPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((AGENTGUARD / "policy.json").read_text(encoding="utf-8"))

    def test_sensitive_path_is_blocked(self):
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "cat ~/.ssh/id_rsa"},
            "session_id": "s1",
            "turn_id": "t1",
            "tool_use_id": "u1",
            "cwd": ".",
        }
        action = normalize_event(event)
        action["_tool_input"] = event["tool_input"]
        blocked, _ = evaluate_action(action, self.policy)
        self.assertTrue(blocked)

    def test_normal_python_command_is_allowed(self):
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "python --version"},
            "session_id": "s1",
            "turn_id": "t1",
            "tool_use_id": "u2",
            "cwd": ".",
        }
        action = normalize_event(event)
        action["_tool_input"] = event["tool_input"]
        blocked, _ = evaluate_action(action, self.policy)
        self.assertFalse(blocked)

    def test_destructive_pattern_is_blocked(self):
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "session_id": "s1",
            "turn_id": "t1",
            "tool_use_id": "u3",
            "cwd": ".",
        }
        action = normalize_event(event)
        action["_tool_input"] = event["tool_input"]
        blocked, _ = evaluate_action(action, self.policy)
        self.assertTrue(blocked)

    def test_file_target_normalization(self):
        event = {"tool_name": "apply_patch", "tool_input": {"file_path": "src/main.py"}}
        action = normalize_event(event)
        self.assertEqual(action["action_type"], "WRITE")
        self.assertEqual(action["target"], "src/main.py")


if __name__ == "__main__":
    unittest.main()
