"""Codex PreToolUse command hook for AgentGuard."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
sys.path.insert(0, str(HERE))

from core import evaluate_action, load_policy, normalize_event  # noqa: E402
from integrity import verify_integrity  # noqa: E402


def emit_block(reason: str) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output, ensure_ascii=False))
    raise SystemExit(0)


def log_record(record: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / "audit.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        emit_block("AgentGuard could not parse the hook event; blocked by fail-closed policy.")

    if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
        emit_block("AgentGuard received an invalid or unexpected hook event.")

    integrity_ok, integrity_message = verify_integrity()
    if not integrity_ok:
        log_record({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "PreToolUse",
            "decision": "BLOCK",
            "reason": integrity_message,
        })
        emit_block("AgentGuard integrity verification failed: " + integrity_message)

    try:
        policy = load_policy(HERE / "policy.json")
    except Exception:
        emit_block("AgentGuard policy could not be loaded; blocked by fail-closed policy.")

    action = normalize_event(event)
    action["_tool_input"] = event.get("tool_input")
    blocked, reason = evaluate_action(action, policy)
    decision = "BLOCK" if blocked else "ALLOW"
    log_record({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "PreToolUse",
        "session_id": action["session_id"],
        "turn_id": action["turn_id"],
        "tool_use_id": action["tool_use_id"],
        "tool_name": action["tool_name"],
        "action_type": action["action_type"],
        "target": action["target"][:300],
        "decision": decision,
        "reason": reason,
        "integrity": "passed",
    })
    if blocked:
        emit_block(reason)
    # Empty stdout + exit 0 means the hook does not block this action.
    raise SystemExit(0)


if __name__ == "__main__":
    main()
