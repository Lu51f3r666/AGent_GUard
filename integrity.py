"""SHA-256 manifest creation and verification for AgentGuard files."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "integrity_manifest.json"
PROTECTED = [
    ROOT / "integrity.py",
    ROOT / "pre_tool_use.py",
    ROOT / "post_tool_use.py",
    ROOT / "codex_hooks" / "pre_tool_use.py",
    ROOT / "codex_hooks" / "post_tool_use.py",
    ROOT / "codex_hooks" / "hook.py",
    ROOT / "core.py",
    ROOT / "policy.json",
    ROOT / "claude_code_hooks" / "hook.py",
    ROOT / "claude_code_hooks" / "config.py",
    ROOT / "claude_code_hooks" / "agentguard_pipeline.py",
    ROOT / "antigravity_hooks" / "hook.py",
    ROOT / "antigravity_hooks" / "config.py",
    ROOT / "antigravity_hooks" / "agentguard_pipeline.py",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rel_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def create_manifest() -> dict:
    missing = [_rel_path(p) for p in PROTECTED if not p.is_file()]
    if missing:
        raise FileNotFoundError("Cannot create manifest; missing files: " + ", ".join(missing))
    manifest = {
        "algorithm": "sha256",
        "purpose": "AgentGuard local integrity baseline",
        "files": {_rel_path(p): sha256_file(p) for p in PROTECTED},
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_integrity() -> tuple[bool, str]:
    if not MANIFEST.is_file():
        return False, "Integrity manifest is missing. Run integrity.py init after reviewing the files."
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if data.get("algorithm") != "sha256" or not isinstance(data.get("files"), dict):
            return False, "Integrity manifest format is invalid."
        expected = data["files"]
        for path in PROTECTED:
            rel = _rel_path(path)
            key = rel if rel in expected else path.name
            if key not in expected:
                return False, f"Integrity manifest does not cover {rel}."
            if not path.is_file():
                return False, f"Protected file is missing: {rel}."
            if sha256_file(path) != expected[key]:
                return False, f"Integrity check failed: {rel} has changed."
        return True, "Integrity check passed."
    except (OSError, ValueError, TypeError) as exc:
        return False, f"Integrity verification failed: {type(exc).__name__}."



if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        created = create_manifest()
        print(f"Created {MANIFEST} covering {len(created['files'])} files.")
    else:
        ok, message = verify_integrity()
        print(message)
        raise SystemExit(0 if ok else 1)
