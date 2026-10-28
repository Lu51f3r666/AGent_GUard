"""Codex Unified Hook Entrypoint for AgentGuard.
Can be invoked directly or dynamically based on the hook event in the payload.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import post_tool_use
import pre_tool_use


def main() -> None:
    # Peek at stdin without consuming it completely if needed, or parse JSON directly
    try:
        raw_input = sys.stdin.read()
        event = json.loads(raw_input)
    except Exception:
        pre_tool_use.emit_block("AgentGuard could not parse Codex hook input.")

    event_name = event.get("hook_event_name")
    # Redirect stdin or invoke logic directly
    import io
    sys.stdin = io.StringIO(raw_input)

    if event_name == "PreToolUse":
        pre_tool_use.main()
    elif event_name == "PostToolUse":
        post_tool_use.main()
    else:
        # Unknown event, default fail-closed for safety
        pre_tool_use.emit_block(f"AgentGuard received unsupported Codex hook event: {event_name}")


if __name__ == "__main__":
    main()
