"""AgentGuard Pipeline for Claude Code hooks.
Connects Claude Code hook events to AgentGuard's integrity check and core security policy.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path to access core.py and integrity.py
HOOKS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HOOKS_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import core  # noqa: E402
from hook import get_session_state, save_session_state  # noqa: E402
from integrity import verify_integrity  # noqa: E402

POLICY_PATH = PROJECT_ROOT / "policy.json"


def handle(event: dict[str, Any]) -> dict[str, str]:
    """Main pipeline handler called for every Claude Code hook event.
    Returns:
        {"verdict": "silent" | "ask" | "deny", "reason": str}
    """
    event_type = event.get("event")
    session_id = str(event.get("session_id") or "unknown")
    state = get_session_state(session_id)

    # 1. Integrity Self-Check (Fail-Closed on pre_tool or critical events)
    integrity_ok, integrity_msg = verify_integrity()
    if not integrity_ok:
        return {
            "verdict": core.DENY,
            "reason": f"AgentGuard self-check failed: {integrity_msg}",
        }

    # 2. Record Task Contract on UserPromptSubmit
    if event_type == "prompt_submit":
        prompt = event.get("prompt") or ""
        scope = core.extract_task_scope(prompt)
        state["task_contract"] = {
            "prompt": prompt[:5000],
            "allowed_paths": scope.get("allowed_paths", []),
            "timestamp": event.get("timestamp"),
        }
        save_session_state(session_id, state)
        return {"verdict": core.SILENT, "reason": ""}

    # 3. Taint Tracking on PostToolUse (detect reads of sensitive files)
    if event_type in ("post_tool", "PostToolUse"):
        tool_name = str(event.get("tool_name") or "")
        tool_input = event.get("tool_input")
        target = core.extract_target(tool_name, tool_input).lower().replace("\\", "/")
        # If target accessed contains sensitive identifiers like .env, record in session taint
        if target and any(frag in target for frag in (".env", "secret", "credential", "token")):
            tainted = state.setdefault("tainted_reads", [])
            if target not in tainted:
                tainted.append(target)
                save_session_state(session_id, state)
        return {"verdict": core.SILENT, "reason": ""}

    # 4. PreToolUse Security Evaluation
    if event_type == "pre_tool":
        try:
            policy = core.load_policy(POLICY_PATH)
        except Exception as e:
            return {
                "verdict": core.DENY,
                "reason": f"AgentGuard policy could not be loaded: {e}",
            }

        action = core.normalize_event(event)
        # Retain tool_input for command/argument analysis
        action["_tool_input"] = event.get("tool_input")
        decision = core.evaluate_security_decision(action, policy, session_state=state)
        core.update_session_denial_state(state, decision["verdict"])
        save_session_state(session_id, state)
        return decision

    # For all other lifecycle events (SessionStart, Stop, etc.), remain silent
    return {"verdict": core.SILENT, "reason": ""}
