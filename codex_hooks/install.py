"""Installer and setup helper for Codex Hooks with AgentGuard."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HOOKS_DIR.parent
SAMPLE_CONFIG = HOOKS_DIR / "hooks.json"
TARGET_CODEX_DIR = PROJECT_ROOT / ".codex"
TARGET_CONFIG = TARGET_CODEX_DIR / "hooks.json"


def install_hooks() -> None:
    """Sets up Codex hooks configuration in .codex/hooks.json."""
    TARGET_CODEX_DIR.mkdir(parents=True, exist_ok=True)
    if not SAMPLE_CONFIG.exists():
        print(f"Error: Sample configuration file not found at {SAMPLE_CONFIG}")
        sys.exit(1)

    shutil.copy2(SAMPLE_CONFIG, TARGET_CONFIG)
    print(f"Successfully installed Codex hooks to: {TARGET_CONFIG}")
    print("Next steps:")
    print("  1. Review hooks using `/hooks` inside Codex if prompted.")
    print("  2. Run `python -m unittest discover -s codex_hooks/tests -v` to verify your hooks.")


if __name__ == "__main__":
    install_hooks()
