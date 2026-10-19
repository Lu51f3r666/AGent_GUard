"""Codex PostToolUse audit hook. Logs metadata, not full tool output."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except Exception:
        # Logging must not break the host workflow after a tool has already run.
        raise SystemExit(0)
    if not isinstance(event, dict):
        raise SystemExit(0)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "PostToolUse",
        "session_id": str(event.get("session_id", "")),
        "turn_id": str(event.get("turn_id", "")),
        "tool_use_id": str(event.get("tool_use_id", "")),
        "tool_name": str(event.get("tool_name", "unknown")),
        "cwd": str(event.get("cwd", "")),
        "result": "tool_completed",
    }
    with (LOG_DIR / "audit.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
