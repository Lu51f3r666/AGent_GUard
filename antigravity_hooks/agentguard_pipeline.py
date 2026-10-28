"""AgentGuard Pipeline for Antigravity IDE.
Evaluates Antigravity tool calls against AgentGuard integrity verification and core security policy.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
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


def extract_antigravity_target_and_type(tool_name: str, tool_args: Any) -> tuple[str, str]:
    """Map Antigravity-specific tools and argument schemas to AgentGuard target and action type."""
    name = (tool_name or "").lower()
    args = tool_args if isinstance(tool_args, dict) else {}

    if name in {"run_command", "bash", "shell", "terminal"}:
        cmd = args.get("CommandLine") or args.get("command") or ""
        return str(cmd), "EXECUTE"

    if name in {"write_to_file", "replace_file_content", "multi_replace_file_content"}:
        target = args.get("TargetFile") or args.get("file_path") or ""
        return str(target), "WRITE"

    if name in {"view_file", "grep_search", "list_dir"}:
        target = args.get("AbsolutePath") or args.get("SearchPath") or args.get("DirectoryPath") or ""
        return str(target), "READ"

    if name in {"read_url_content", "search_web", "browser_subagent"}:
        target = args.get("Url") or args.get("query") or args.get("Task") or ""
        return str(target), "NETWORK"

    # Default fallback to core extraction
    fallback_target = core.extract_target(tool_name, tool_args)
    fallback_type = core.classify_action(tool_name, tool_args)
    return fallback_target, fallback_type


def handle(event: dict[str, Any]) -> dict[str, str]:
    """Evaluate Antigravity lifecycle events through AgentGuard security engine."""
    event_type = event.get("event")
    session_id = str(event.get("session_id") or "unknown")
    state = get_session_state(session_id)

    # 1. Self-Check (Integrity baseline verification)
    integrity_ok, integrity_msg = verify_integrity()
    if not integrity_ok:
        return {
            "verdict": core.DENY,
            "reason": f"AgentGuard self-check failed: {integrity_msg}",
        }

    # 2. Taint Tracking on PostToolUse
    if event_type == "post_tool":
        tool_name = str(event.get("tool_name") or "")
        tool_input = event.get("tool_input")
        target, _ = extract_antigravity_target_and_type(tool_name, tool_input)
        target_lower = target.lower().replace("\\", "/")
        if target and any(frag in target_lower for frag in (".env", "secret", "credential", "token")):
            tainted = state.setdefault("tainted_reads", [])
            if target not in tainted:
                tainted.append(target)
                save_session_state(session_id, state)
        return {"verdict": core.SILENT, "reason": ""}

    # 3. PreToolUse Policy Evaluation
    if event_type == "pre_tool":
        try:
            policy = core.load_policy(POLICY_PATH)
        except Exception as e:
            return {
                "verdict": core.DENY,
                "reason": f"AgentGuard policy could not be loaded: {e}",
            }

        tool_name = str(event.get("tool_name") or "unknown")
        tool_input = event.get("tool_input") or {}
        target, action_type = extract_antigravity_target_and_type(tool_name, tool_input)

        # Build action dictionary for core policy evaluation
        action = {
            "session_id": session_id,
            "tool_name": tool_name,
            "action_type": action_type,
            "target": target,
            "cwd": str(event.get("cwd") or ""),
            "_tool_input": {
                "command": target if action_type == "EXECUTE" else tool_input.get("command", ""),
                **tool_input,
            },
        }

        decision = core.evaluate_security_decision(action, policy, session_state=state)
        core.update_session_denial_state(state, decision["verdict"])
        save_session_state(session_id, state)
        return decision

    return {"verdict": core.SILENT, "reason": ""}
