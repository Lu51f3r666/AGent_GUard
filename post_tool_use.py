"""Backward-compatibility forwarder for Codex PostToolUse hook."""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODEX_HOOKS = HERE / "codex_hooks"
if str(CODEX_HOOKS) not in sys.path:
    sys.path.insert(0, str(CODEX_HOOKS))

import post_tool_use  # noqa: E402

if __name__ == "__main__":
    post_tool_use.main()
