"""Deterministic action normalization and policy checks for the starter adapter."""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def extract_target(tool_name: str, tool_input: Any) -> str:
    """Extract a best-effort target from tool-specific arguments."""
    if not isinstance(tool_input, dict):
        return ""
    for key in ("file_path", "path", "filename", "target", "directory", "cwd"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # Shell and patch tools commonly use command; this is a heuristic, not a parser.
    command = tool_input.get("command")
    if isinstance(command, str):
        return command[:1000]
    return ""


def classify_action(tool_name: str, tool_input: Any) -> str:
    name = tool_name.lower()
    if name in {"bash", "shell", "terminal", "unified_exec"}:
        return "EXECUTE"
    if "read" in name or "search" in name or "list" in name:
        return "READ"
    if "write" in name or "edit" in name or "patch" in name or name in {"apply_patch"}:
        return "WRITE"
    if name.startswith("mcp__"):
        return "MCP"
    if isinstance(tool_input, dict) and any(k in tool_input for k in ("file_path", "path", "filename")):
        return "FILE_OPERATION"
    return "UNKNOWN"


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(event.get("tool_name", "unknown"))
    tool_input = event.get("tool_input")
    target = extract_target(tool_name, tool_input)
    return {
        "session_id": str(event.get("session_id", "")),
        "turn_id": str(event.get("turn_id", "")),
        "tool_use_id": str(event.get("tool_use_id", "")),
        "tool_name": tool_name,
        "action_type": classify_action(tool_name, tool_input),
        "target": target[:1000],
        "cwd": str(event.get("cwd", "")),
    }


def evaluate_action(action: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str]:
    """Return (blocked, reason). Conservative examples; not a full shell parser."""
    target = str(action.get("target", "")).replace("\\", "/").lower()
    for fragment in policy.get("sensitive_path_fragments", []):
        if str(fragment).replace("\\", "/").lower() in target:
            return True, f"Policy blocked access to a sensitive-looking target ({fragment})."

    tool_name = str(action.get("tool_name", "")).lower()
    tool_input = action.get("_tool_input")
    command = ""
    if isinstance(tool_input, dict):
        command = _stringify(tool_input.get("command", ""))
    if tool_name in {"bash", "shell", "terminal", "unified_exec"}:
        for pattern in policy.get("blocked_command_patterns", []):
            try:
                if re.search(pattern, command):
                    return True, "Policy blocked a command matching a destructive-operation rule."
            except re.error:
                return True, "Policy configuration contains an invalid regular expression; blocked for safety."
    return False, "No deterministic blocking rule matched."


def load_policy(path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
