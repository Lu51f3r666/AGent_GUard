"""Pipeline entry point. REPLACE THIS FILE with the real pipeline
(or point config.PIPELINE_MODULE at your own module).

handle(event) is called once for every hook event (all 12 types) with the
normalized event dict documented at the top of hook.py. It must return

    {"verdict": "silent" | "ask" | "deny", "reason": str}

Only the verdict for event["event"] == "pre_tool" is used; for every other
event the return value is ignored, but the call lets the pipeline track
context (task text, subagent start/stop, tool results).

There is no "allow": anything other than silent/ask/deny is treated as an
error (silent, or deny under FAIL_CLOSED). Raising is safe: the error is
logged and the agent continues.

Per-session state (task text, run tag):
    from hook import get_session_state
    get_session_state(event["session_id"])
"""


def handle(event: dict) -> dict:
    return {"verdict": "silent", "reason": ""}
