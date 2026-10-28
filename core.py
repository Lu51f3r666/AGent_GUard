"""Deterministic action normalization and policy checks for AgentGuard."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

SILENT = "silent"
ASK = "ask"
DENY = "deny"
GENESIS_HASH = "0" * 64


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
    for key in ("file_path", "path", "filename", "target", "directory", "cwd", "url"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    command = tool_input.get("command")
    if isinstance(command, str):
        return command[:1000]
    return ""


def classify_action(tool_name: str, tool_input: Any) -> str:
    name = tool_name.lower()
    if name in {"bash", "shell", "terminal", "unified_exec"}:
        return "EXECUTE"
    if any(k in name for k in ("read", "view", "grep", "glob", "search", "list")):
        return "READ"
    if any(k in name for k in ("write", "edit", "patch")) or name in {"apply_patch", "notebookeditcell"}:
        return "WRITE"
    if any(k in name for k in ("webfetch", "browse", "fetch", "http")):
        return "NETWORK"
    if name in {"task", "architect"}:
        return "SUBAGENT"
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
        "_tool_input": tool_input,
    }


def extract_task_scope(prompt: str) -> dict[str, Any]:
    """Parse user prompt into an authorized scope of files, environments, and operations."""
    if not prompt or not isinstance(prompt, str):
        return {"allowed_paths": [], "prompt": ""}
    # Extract filename patterns (e.g. filename.ext or path/to/file.ext)
    file_pattern = r'[a-zA-Z0-9_\-\./\\]+\.[a-zA-Z0-9_]{1,10}'
    found_files = re.findall(file_pattern, prompt)
    cleaned_files = []
    for f in found_files:
        clean = f.strip("`'\"()[],.:;<>").replace("\\", "/").lower()
        if clean and not clean.endswith(".") and len(clean) > 2:
            cleaned_files.append(clean)
    return {
        "prompt": prompt,
        "allowed_paths": sorted(list(set(cleaned_files))),
    }


def update_session_denial_state(session_state: dict[str, Any], verdict: str) -> None:
    """Updates consecutive and total denials; freezes session if threshold reached (3 consecutive or 20 total)."""
    if not isinstance(session_state, dict):
        return
    if verdict == DENY:
        session_state["consecutive_denials"] = session_state.get("consecutive_denials", 0) + 1
        session_state["total_denials"] = session_state.get("total_denials", 0) + 1
        if session_state["consecutive_denials"] >= 3 or session_state["total_denials"] >= 20:
            session_state["frozen"] = True
    elif verdict == SILENT:
        session_state["consecutive_denials"] = 0


def build_audit_entry(
    event_data: dict[str, Any],
    prev_hash: str = GENESIS_HASH,
    seq: int = 1,
) -> dict[str, Any]:
    """Creates a tamper-evident audit log record chained by SHA-256."""
    entry = {
        "seq": seq,
        "prev_hash": prev_hash,
        "timestamp": str(event_data.get("timestamp") or ""),
        "event": str(event_data.get("event") or ""),
        "session_id": str(event_data.get("session_id") or ""),
        "tool_name": str(event_data.get("tool_name") or ""),
        "action_type": str(event_data.get("action_type") or ""),
        "target": str(event_data.get("target") or "")[:300],
        "verdict": str(event_data.get("verdict") or event_data.get("decision") or ""),
        "reason": str(event_data.get("reason") or ""),
    }
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["entry_hash"] = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
    return entry


def verify_audit_chain(records: list[dict[str, Any]]) -> tuple[bool, str]:
    """Verifies the cryptographic integrity of a hash-chained audit log."""
    prev_hash = GENESIS_HASH
    for idx, rec in enumerate(records):
        expected_seq = idx + 1
        if rec.get("seq") != expected_seq:
            return False, f"Sequence break at index {idx}: expected {expected_seq}, got {rec.get('seq')}"
        if rec.get("prev_hash") != prev_hash:
            return False, f"Broken hash chain at sequence {rec.get('seq')}: prev_hash mismatch"
        data = {k: v for k, v in rec.items() if k != "entry_hash"}
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
        computed_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
        if computed_hash != rec.get("entry_hash"):
            return False, f"Tampered entry detected at sequence {rec.get('seq')}: hash mismatch"
        prev_hash = rec.get("entry_hash")
    return True, "Audit chain integrity verified."


def evaluate_security_decision(
    action: dict[str, Any],
    policy: dict[str, Any],
    session_state: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Evaluate an action against policy rules.
    Returns:
        {"verdict": "silent" | "ask" | "deny", "reason": str}
    """
    # 0. Session Defense: Check if session is frozen due to repeated denials
    if session_state and session_state.get("frozen"):
        return {
            "verdict": DENY,
            "reason": "Session is frozen: Exceeded security denial limit (3 consecutive denials). Escalated to human.",
        }

    target = str(action.get("target", "")).replace("\\", "/").lower()
    tool_name = str(action.get("tool_name", "")).lower()
    action_type = action.get("action_type", "")
    tool_input = action.get("_tool_input")
    command = ""
    if isinstance(tool_input, dict):
        command = _stringify(tool_input.get("command", "")).lower()

    # 1. Tamper Resistance: Block modifications to AgentGuard security files
    if action_type in {"WRITE", "FILE_OPERATION"} or (action_type == "EXECUTE" and any(op in command for op in (">", "rm ", "del ", "move ", "remove"))):
        for protected in policy.get("protected_files", []):
            prot_name = protected.lower()
            if prot_name in target or (command and prot_name in command):
                return {
                    "verdict": DENY,
                    "reason": f"Tamper prevention: Cannot modify or delete AgentGuard security file ({protected}).",
                }

    # 2. Blocked Destructive Commands
    if action_type == "EXECUTE":
        for pattern in policy.get("blocked_command_patterns", []):
            try:
                if re.search(pattern, command):
                    return {
                        "verdict": DENY,
                        "reason": f"Policy blocked command matching destructive-operation rule.",
                    }
            except re.error:
                return {
                    "verdict": DENY,
                    "reason": "Policy configuration contains an invalid regular expression; blocked for safety.",
                }

    # 3. Denied Path Fragments (Credentials, SSH keys, private tokens)
    deny_fragments = policy.get("deny_path_fragments") or policy.get("sensitive_path_fragments", [])
    for fragment in deny_fragments:
        frag_clean = str(fragment).replace("\\", "/").lower()
        if frag_clean in target or (command and frag_clean in command):
            return {
                "verdict": DENY,
                "reason": f"Policy blocked access to sensitive credentials target ({fragment}).",
            }

    # 4. Ask Path Fragments (.env, package configs requiring confirmation)
    for fragment in policy.get("ask_path_fragments", []):
        frag_clean = str(fragment).replace("\\", "/").lower()
        if frag_clean in target or (command and frag_clean in command):
            return {
                "verdict": ASK,
                "reason": f"Access to sensitive configuration file ({fragment}) requires user confirmation.",
            }

    # 5. Taint Tracking / Network Egress after sensitive file read
    if session_state and session_state.get("tainted_reads"):
        # If sensitive files were read in this session, check for outbound egress
        is_egress = action_type == "NETWORK"
        if action_type == "EXECUTE":
            for egress_pat in policy.get("egress_command_patterns", []):
                if re.search(egress_pat, command):
                    is_egress = True
                    break
        if is_egress:
            tainted = session_state.get("tainted_reads")
            return {
                "verdict": ASK,
                "reason": f"Taint tracking alert: Network transmission attempted after sensitive files were read ({tainted}).",
            }

    # 6. Target-Binding Check against Task Contract (Layer 1)
    if session_state and isinstance(session_state.get("task_contract"), dict):
        contract = session_state["task_contract"]
        allowed_paths = contract.get("allowed_paths", [])
        if allowed_paths and action_type in {"WRITE", "FILE_OPERATION"}:
            target_clean = target.replace("\\", "/").lower()
            is_authorized = any(
                (allowed in target_clean or target_clean in allowed or Path(target_clean).name == Path(allowed).name)
                for allowed in allowed_paths
            )
            # Allow tests / temporary scratch files if not an out-of-scope source file
            if not is_authorized and not any(k in target_clean for k in ("scratch", "tmp", "temp")):
                return {
                    "verdict": ASK,
                    "reason": f"Target-binding deviation: Target '{action.get('target')}' is outside the authorized task scope {allowed_paths}.",
                }

    # 7. Fast Path for pure in-project reads
    if action_type == "READ":
        return {"verdict": SILENT, "reason": "Fast path: In-project read", "fast_path": True}

    # 8. Safe / Benign Action
    return {"verdict": SILENT, "reason": ""}


def evaluate_action(action: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str]:
    """Legacy backward-compatible evaluation: returns (blocked: bool, reason: str)."""
    decision = evaluate_security_decision(action, policy)
    is_blocked = decision["verdict"] in (DENY, ASK)
    reason = decision["reason"] or "No deterministic blocking rule matched."
    return is_blocked, reason


def load_policy(path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
