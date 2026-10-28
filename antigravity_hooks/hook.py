#!/usr/bin/env python3
"""Antigravity IDE hook adapter for AgentGuard.
Receives lifecycle events from Antigravity IDE on stdin, normalizes them,
evaluates them through AgentGuard pipeline, logs audit records, and returns
decisions (allow, ask, deny) on stdout.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any

HERE = os.path.dirname(os.path.realpath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

AGENT_KIND = "antigravity_ide"

# Supported Antigravity decisions
ALLOW = "allow"
ASK = "ask"
DENY = "deny"
FORCE_ASK = "force_ask"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _config():
    import config
    return config


def log_path() -> str:
    return getattr(_config(), "LOG_PATH", None) or os.path.join(HERE, "data", "events.jsonl")


def state_dir() -> str:
    return getattr(_config(), "STATE_DIR", None) or os.path.join(HERE, "data", "state")


def timestamp() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1000):03d}Z"


def truncate(value, limit: int, items: int):
    """Copy of value with long strings and lists cut (for the log only)."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"...[+{len(value) - limit} chars]"
    if isinstance(value, dict):
        return {str(k)[:limit]: truncate(v, limit, items) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        out = [truncate(v, limit, items) for v in value[:items]]
        if len(value) > items:
            out.append(f"...[+{len(value) - items} items]")
        return out
    return value


def append_log(record: dict, path: str = None) -> None:
    """One os.write on an O_APPEND fd for concurrency safety."""
    path = path or log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8", "backslashreplace")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def _state_file(session_id: str) -> str:
    return os.path.join(state_dir(), _SAFE_NAME.sub("_", session_id or "unknown")[:128] + ".json")


def get_session_state(session_id: str) -> dict:
    try:
        with open(_state_file(session_id), encoding="utf-8") as f:
            state = json.load(f)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_session_state(session_id: str, state: dict) -> None:
    path = _state_file(session_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8", errors="backslashreplace") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, path)


def detect_event_name(payload: dict) -> str:
    """Detect Antigravity event type from payload structure."""
    if "hook_event_name" in payload:
        name = payload["hook_event_name"]
        return "pre_tool" if name == "PreToolUse" else ("post_tool" if name == "PostToolUse" else str(name).lower())
    if "hookEventName" in payload:
        name = payload["hookEventName"]
        return "pre_tool" if name == "PreToolUse" else ("post_tool" if name == "PostToolUse" else str(name).lower())

    if "toolCall" in payload:
        if "error" in payload or "toolResponse" in payload or "isPost" in payload:
            return "post_tool"
        return "pre_tool"
    if "invocationNum" in payload:
        return "pre_invocation"
    if "terminationReason" in payload:
        return "stop"
    return "unknown"


def normalize(payload: dict) -> dict:
    """Normalize Antigravity payload to AgentGuard unified schema."""
    event_name = detect_event_name(payload)
    tool_call = payload.get("toolCall") or {}
    tool_name = tool_call.get("name") if isinstance(tool_call, dict) else None
    tool_args = tool_call.get("args") if isinstance(tool_call, dict) else None

    session_id = str(payload.get("conversationId") or payload.get("session_id") or "unknown")

    return {
        "agent_kind": AGENT_KIND,
        "event": event_name,
        "session_id": session_id,
        "timestamp": timestamp(),
        "tool_name": tool_name,
        "tool_input": tool_args if isinstance(tool_args, dict) else None,
        "cwd": payload.get("workspacePaths", [None])[0] if payload.get("workspacePaths") else None,
        "step_idx": payload.get("stepIdx"),
        "error": payload.get("error"),
        "extra": payload,
    }


def call_pipeline(event: dict, cfg) -> tuple[dict | None, float, str | None]:
    t0 = time.perf_counter()
    try:
        import importlib
        pipeline = importlib.import_module(cfg.PIPELINE_MODULE)
        result = pipeline.handle(event)
        return result, round((time.perf_counter() - t0) * 1000, 2), None
    except BaseException as exc:
        return None, round((time.perf_counter() - t0) * 1000, 2), f"{exc.__class__.__name__}: {exc}"[:2000]


def render(event_name: str, decision: dict | None) -> str:
    """Format decision output according to Antigravity hook protocol."""
    if event_name == "pre_tool":
        if not decision:
            decision = {"verdict": "silent", "reason": ""}
        verdict = decision.get("verdict", "silent")
        reason = decision.get("reason", "")

        if verdict == "deny":
            return json.dumps({
                "decision": DENY,
                "reason": f"[AgentGuard] {reason}" if reason else "[AgentGuard] Blocked by security policy",
            }, ensure_ascii=False)
        elif verdict == "ask":
            return json.dumps({
                "decision": ASK,
                "reason": f"[AgentGuard] {reason}" if reason else "[AgentGuard] Human confirmation requested",
            }, ensure_ascii=False)
        else:
            return json.dumps({
                "decision": ALLOW,
                "reason": "",
            }, ensure_ascii=False)

    elif event_name == "pre_invocation":
        return json.dumps({"injectSteps": []})
    elif event_name == "post_tool":
        return json.dumps({})
    elif event_name == "stop":
        return json.dumps({})
    return json.dumps({})


def process(raw: bytes) -> str:
    cfg = _config()
    payload = json.loads(raw.decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")

    event = normalize(payload)
    record = truncate(event, cfg.MAX_LOG_STRING, cfg.MAX_LOG_ITEMS)

    result, latency_ms, error = call_pipeline(event, cfg)
    record["latency_ms"] = latency_ms
    if error:
        record["error"] = error

    if result is not None:
        record["verdict"] = result.get("verdict")
        record["reason"] = result.get("reason")
    elif cfg.FAIL_CLOSED and event["event"] == "pre_tool":
        result = {"verdict": "deny", "reason": f"Pipeline failure under FAIL_CLOSED ({error})"}
        record["verdict"] = "deny"

    append_log(record)
    return render(event["event"], result)


def main() -> None:
    raw = sys.stdin.buffer.read()
    try:
        out = process(raw)
    except BaseException as exc:
        cfg = _config()
        if getattr(cfg, "FAIL_CLOSED", True):
            out = json.dumps({
                "decision": DENY,
                "reason": f"[AgentGuard] Monitor error: {exc}",
            })
        else:
            out = json.dumps({"decision": ALLOW, "reason": ""})
    sys.stdout.write(out)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
