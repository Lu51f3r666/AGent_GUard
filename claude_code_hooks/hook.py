#!/usr/bin/env python3
"""Claude Code hook entry script (one script for all 12 events).

Flow per call: stdin JSON -> normalize() -> session state -> pipeline handle()
-> one log line -> stdout (only an ask/deny decision for PreToolUse).

Rules: never output "allow"; nothing but the decision goes to stdout (for
SessionStart and UserPromptSubmit, stdout would enter Claude's context);
always exit 0; on any failure log it and stay silent, except PreToolUse under
FAIL_CLOSED, which is denied.

Normalized event (plain JSON-serializable dict, every key always present):
  agent_kind       "claude_code"
  event            normalized name, see EVENTS below
  session_id       str
  timestamp        ISO 8601 UTC
  cwd              str | None
  tool_name        str | None
  tool_input       dict | None
  tool_response    any (post-tool events)
  prompt           str | None (prompt_submit)
  agent_id         str | None (set when a subagent acts)
  agent_type       str | None
  permission_mode  str | None
  run_tag          str | None (from a [run:XXXX] prompt tag)
  extra            dict: every other payload field, unmodified
"""
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python -I does not add the script dir

AGENT_KIND = "claude_code"

# Claude Code hook event -> normalized event name.
EVENTS = {
    "SessionStart": "session_start",
    "UserPromptSubmit": "prompt_submit",
    "PreToolUse": "pre_tool",               # the only event whose decision is used
    "PostToolUse": "post_tool",
    "PostToolUseFailure": "post_tool_failure",
    "PermissionRequest": "permission_request",
    "PermissionDenied": "permission_denied",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "Stop": "stop",
    "SessionEnd": "session_end",
    "ConfigChange": "config_change",
}
# Registered with matcher "*"; the others without a matcher.
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied")

# Payload fields with their own slot in the event; everything else goes to "extra".
MAPPED = ("hook_event_name", "session_id", "cwd", "tool_name", "tool_input", "tool_response",
          "prompt", "agent_id", "agent_type", "permission_mode")

# Verdicts. There is deliberately no "allow".
SILENT, ASK, DENY = "silent", "ask", "deny"
VERDICTS = (SILENT, ASK, DENY)

RUN_TAG = re.compile(r"\[run:([A-Za-z0-9._-]{1,64})\]")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


# --- paths, log, session state ---------------------------------------------

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
    """One os.write on an O_APPEND fd, so parallel hooks never interleave lines."""
    path = path or log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # backslashreplace turns lone surrogates into \udxxx, which is still valid JSON.
    line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8", "backslashreplace")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def _state_file(session_id: str) -> str:
    return os.path.join(state_dir(), _SAFE_NAME.sub("_", session_id or "unknown")[:128] + ".json")


def get_session_state(session_id: str) -> dict:
    """Per-session state: {"task", "run_tag", "prompts", "updated"}; {} if unknown.
    For the pipeline: `from hook import get_session_state`."""
    try:
        with open(_state_file(session_id), encoding="utf-8") as f:
            state = json.load(f)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_session_state(session_id: str, state: dict) -> None:
    """Atomic: write a temp file, then rename over the old one."""
    path = _state_file(session_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8", errors="backslashreplace") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, path)


# --- in: Claude Code JSON -> normalized event ---------------------------------

def _str(value):
    return value if isinstance(value, str) else None


def normalize(payload: dict) -> dict:
    name = payload.get("hook_event_name")
    tool_input = payload.get("tool_input")
    return {
        "agent_kind": AGENT_KIND,
        "event": EVENTS.get(name, str(name)),   # unknown future events keep their own name
        "session_id": str(payload.get("session_id") or "unknown"),
        "timestamp": timestamp(),
        "cwd": _str(payload.get("cwd")),
        "tool_name": _str(payload.get("tool_name")),
        "tool_input": tool_input if isinstance(tool_input, dict) else None,
        "tool_response": payload.get("tool_response"),
        "prompt": _str(payload.get("prompt")),
        "agent_id": _str(payload.get("agent_id")),
        "agent_type": _str(payload.get("agent_type")),
        "permission_mode": _str(payload.get("permission_mode")),
        "run_tag": None,                          # filled from session state
        "extra": {k: v for k, v in payload.items() if k not in MAPPED},
    }


def update_session(event: dict, max_task_chars: int) -> None:
    """Save task text and run tag on a prompt; put the session's run tag on the event."""
    sid = event["session_id"]
    state = get_session_state(sid)
    if event["event"] == "prompt_submit":
        prompt = event.get("prompt") or ""
        state["task"] = prompt[:max_task_chars]
        m = RUN_TAG.search(prompt)
        if m:
            state["run_tag"] = m.group(1)
        state["prompts"] = state.get("prompts", 0) + 1
        state["updated"] = event["timestamp"]
        save_session_state(sid, state)
    event["run_tag"] = state.get("run_tag")


# --- pipeline ------------------------------------------------------------------

def validate_decision(value) -> dict:
    """Accept only {"verdict": silent|ask|deny, "reason": str}; raise otherwise."""
    if not isinstance(value, dict):
        raise ValueError(f"pipeline returned {type(value).__name__}, expected dict")
    verdict = value.get("verdict")
    if verdict not in VERDICTS:
        raise ValueError(f"pipeline returned invalid verdict {verdict!r}")
    reason = value.get("reason", "")
    if not isinstance(reason, str):
        raise ValueError("pipeline returned a non-string reason")
    return {"verdict": verdict, "reason": reason}


def _http_handle(event: dict, cfg) -> dict:
    import http.client
    import urllib.parse

    url = urllib.parse.urlsplit(cfg.PIPELINE_URL)
    cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = cls(url.hostname, url.port, timeout=cfg.PIPELINE_TIMEOUT)
    try:
        body = json.dumps(event, default=str).encode("utf-8", "backslashreplace")
        conn.request("POST", url.path or "/", body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read(1 << 20)
        if resp.status != 200:
            raise RuntimeError(f"pipeline HTTP {resp.status}")
        return json.loads(data)
    finally:
        conn.close()


def call_pipeline(event: dict, cfg):
    """Returns (decision or None, latency_ms, error or None). Never raises."""
    t0 = time.perf_counter()
    try:
        if cfg.PIPELINE_MODE == "http":
            result = _http_handle(event, cfg)
        elif cfg.PIPELINE_MODE == "module":
            import importlib
            result = importlib.import_module(cfg.PIPELINE_MODULE).handle(event)
        else:
            raise ValueError(f"unknown PIPELINE_MODE {cfg.PIPELINE_MODE!r}")
        return validate_decision(result), round((time.perf_counter() - t0) * 1000, 2), None
    except BaseException as exc:  # noqa: BLE001 - a broken pipeline must not break the agent
        return None, round((time.perf_counter() - t0) * 1000, 2), f"{exc.__class__.__name__}: {exc}"[:2000]


# --- out: decision -> Claude Code JSON ------------------------------------------

def render(decision: dict):
    """PreToolUse output for ask/deny; None (print nothing) for anything else.
    "allow" can never be produced: only these two verdicts are passed through."""
    verdict = decision.get("verdict")
    if verdict not in (ASK, DENY):
        return None
    reason = decision.get("reason") or "no reason given"
    verb = "blocked" if verdict == DENY else "asks you to confirm"
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict,
            "permissionDecisionReason": f"[AgentGuard] {reason}",
        },
        "systemMessage": f"AgentGuard {verb} this action: {reason}",
    })


# --- main flow -----------------------------------------------------------------

def process(raw: bytes):
    """Returns the text for stdout, or None for silent."""
    cfg = _config()
    payload = json.loads(raw.decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise ValueError("hook payload is not a JSON object")

    event = normalize(payload)
    update_session(event, cfg.MAX_TASK_CHARS)  # before the pipeline, so it sees the task
    record = truncate(event, cfg.MAX_LOG_STRING, cfg.MAX_LOG_ITEMS)

    result, latency_ms, error = call_pipeline(event, cfg)
    record["latency_ms"] = latency_ms
    if error:
        record["error"] = error

    out = {"verdict": SILENT, "reason": ""}
    if event["event"] == "pre_tool":
        if result is not None:
            record["verdict"], record["reason"] = result["verdict"], result["reason"]
            out = result
        elif cfg.FAIL_CLOSED:
            out = {"verdict": DENY, "reason": f"Monitor pipeline failed and FAIL_CLOSED is on ({error})"}
        if cfg.LOG_ONLY and out["verdict"] != SILENT:
            record["log_only_suppressed"] = out
            out = {"verdict": SILENT, "reason": ""}
        record["output"] = out["verdict"]

    append_log(record)
    return render(out)


FAIL_CLOSED_JSON = json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "[AgentGuard] Monitor error and FAIL_CLOSED is on; see data/events.jsonl",
    },
    "systemMessage": "AgentGuard blocked this action: monitor error and FAIL_CLOSED is on",
})


def on_crash(raw: bytes, exc: BaseException):
    """Our own code failed (or the input was malformed): log, then silent or fail-closed deny."""
    import traceback

    fail_closed, path = False, os.path.join(HERE, "data", "events.jsonl")
    try:
        fail_closed = bool(_config().FAIL_CLOSED)
        path = log_path()
    except BaseException:
        pass
    text = raw.decode("utf-8", "replace")
    try:
        name = json.loads(text).get("hook_event_name")
    except BaseException:
        name = "PreToolUse" if '"PreToolUse"' in text else None
    denied = fail_closed and name == "PreToolUse"
    try:
        append_log({
            "timestamp": timestamp(),
            "event": "monitor_error",
            "hook_event_name": name,
            "error": f"{exc.__class__.__name__}: {exc}"[:2000],
            "traceback": traceback.format_exc()[-4000:],
            "raw_input": text[:2000],
            "output": DENY if denied else SILENT,
        }, path)
    except BaseException:
        pass
    return FAIL_CLOSED_JSON if denied else None


def main() -> None:
    raw = b""
    try:
        raw = sys.stdin.buffer.read()
        out = process(raw)
    except BaseException as exc:  # noqa: BLE001 - must never escape
        out = on_crash(raw, exc)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    finally:
        os._exit(0)
