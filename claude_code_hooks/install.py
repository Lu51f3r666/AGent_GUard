#!/usr/bin/env python3
"""Register (or remove) our 12 Claude Code hooks in ~/.claude/settings.json.

  python3 install.py [--dry-run] [--uninstall] [--python PATH]

The hooks run hook.py from this folder in place, so edits here take effect on
the next hook call. The settings file is backed up before every write. Our
hooks are recognized by MARKER in the command; other hooks are never touched.
Respects $CLAUDE_CONFIG_DIR.
"""
import argparse
import json
import os
import shlex
import shutil
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

from hook import EVENTS, TOOL_EVENTS  # noqa: E402

MARKER = "claude_code_hooks/hook.py"
HOOK_TIMEOUT = 10  # seconds


def settings_path() -> str:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.join(base, "settings.json")


def hook_command(python: str) -> str:
    return f"{shlex.quote(python)} -I -B {shlex.quote(os.path.join(HERE, 'hook.py'))}"


def is_ours(handler) -> bool:
    return isinstance(handler, dict) and isinstance(handler.get("command"), str) and MARKER in handler["command"]


def load_settings(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: top level is not a JSON object; refusing to touch it")
    return data


def strip_ours(settings: dict) -> int:
    """Remove our handlers in place; drop groups/events left empty by that. Returns count removed."""
    removed = 0
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list) or not handlers:
                kept_groups.append(group)
                continue
            kept = [h for h in handlers if not is_ours(h)]
            removed += len(handlers) - len(kept)
            if kept:
                kept_groups.append({**group, "hooks": kept})
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    return removed


def our_hooks(command: str) -> dict:
    """The settings.json "hooks" entries we register (print them with --dry-run)."""
    out = {}
    for event in EVENTS:
        group = {"hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT}]}
        out[event] = [{"matcher": "*", **group} if event in TOOL_EVENTS else group]
    return out


def add_ours(settings: dict, command: str) -> None:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = settings["hooks"] = {}
    for event, groups in our_hooks(command).items():
        if not isinstance(hooks.get(event), list):
            hooks[event] = []
        hooks[event].extend(groups)


def backup(path: str):
    if not os.path.exists(path):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst, n = f"{path}.agentguard-bak-{stamp}", 1
    while os.path.exists(dst):
        dst, n = f"{path}.agentguard-bak-{stamp}-{n}", n + 1
    shutil.copy2(path, dst)
    return dst


def write_json_atomic(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".agentguard.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    ap.add_argument("--uninstall", action="store_true", help="remove our hooks")
    ap.add_argument("--python", default="python3", help="interpreter used in the hook command")
    args = ap.parse_args(argv)

    path = settings_path()
    settings = load_settings(path)
    dry = "[dry-run] " if args.dry_run else ""
    removed = strip_ours(settings)

    if args.uninstall:
        print(f"{dry}remove {removed} AgentGuard hook handler(s) from {path}")
        if removed and not args.dry_run:
            print(f"backup: {backup(path)}")
            write_json_atomic(path, settings)
        return 0

    command = hook_command(args.python)
    add_ours(settings, command)
    print(f"{dry}{'replace' if removed else 'add'} hooks in {path} for: {', '.join(EVENTS)}")
    print(f"{dry}command: {command}")
    if args.dry_run:
        print(json.dumps({"hooks": our_hooks(command)}, indent=2))
        return 0
    bak = backup(path)
    if bak:
        print(f"backup: {bak}")
    write_json_atomic(path, settings)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
