#!/usr/bin/env python3
"""Installer and manager for AgentGuard hooks in Antigravity IDE.
Configures workspace hooks in .agents/hooks.json or global configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_HOOKS_FILE = PROJECT_ROOT / ".agents" / "hooks.json"


def load_hooks(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: Could not parse existing {path}: {e}")
        return {}


def save_hooks(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install AgentGuard hooks for Antigravity IDE")
    parser.add_argument("--global", dest="is_global", action="store_true", help="Install into global ~/.gemini/config/hooks.json")
    parser.add_argument("--uninstall", action="store_true", help="Remove AgentGuard hooks")
    parser.add_argument("--python", default=sys.executable, help="Python executable path")
    args = parser.parse_args()

    if args.is_global:
        target_path = Path.home() / ".gemini" / "config" / "hooks.json"
    else:
        target_path = DEFAULT_HOOKS_FILE

    config = load_hooks(target_path)

    if args.uninstall:
        if "agentguard" in config:
            del config["agentguard"]
            save_hooks(target_path, config)
            print(f"Successfully uninstalled AgentGuard hooks from {target_path}")
        else:
            print(f"AgentGuard hook not found in {target_path}")
        return

    hook_cmd = f"{args.python} antigravity_hooks/hook.py"

    config["agentguard"] = {
        "enabled": True,
        "PreToolUse": [
            {
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": hook_cmd,
                        "timeout": 15,
                    }
                ],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": hook_cmd,
                        "timeout": 10,
                    }
                ],
            }
        ],
    }

    save_hooks(target_path, config)
    print(f"Successfully installed AgentGuard hooks into {target_path}")
    print(f"Hook command configured: {hook_cmd}")


if __name__ == "__main__":
    main()
