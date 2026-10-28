# Codex Hooks for AgentGuard

This package connects **AgentGuard** to **OpenAI Codex** command hooks.

Codex supports lifecycle hooks before and after tool execution:
- `PreToolUse`: Intercepts and validates the tool call before execution.
- `PostToolUse`: Audits tool completion metadata after execution.

---

## Architecture and Flow

```text
Codex tool invocation
       |
       v (stdin: JSON event)
codex_hooks/pre_tool_use.py
       |
       +--> Verify Integrity (SHA-256 self-check across protected files)
       +--> Normalize Codex tool event
       +--> Evaluate Security Rules (AgentGuard policy engine in core.py)
       |
       v (stdout: JSON response)
Codex decision:
  - ALLOW (Empty stdout + exit 0) --> Tool proceeds
  - DENY  (hookSpecificOutput.permissionDecision = "deny") --> Action blocked
       |
       v
Tool runs (if allowed)
       |
       v
codex_hooks/post_tool_use.py --> Audit record logged to codex_hooks/logs/audit.jsonl
```

---

## Directory Structure

```
codex_hooks/
├── pre_tool_use.py        # PreToolUse hook interceptor and policy gate
├── post_tool_use.py       # PostToolUse audit logger
├── hook.py                # Unified dispatcher entrypoint
├── hooks.json             # Sample hook configuration
├── install.py             # Setup script copying config to .codex/hooks.json
├── CodexHooks.md          # Documentation
├── logs/                  # Local audit logs (audit.jsonl)
└── tests/                 # Unit test suite for Codex hooks
```

---

## Installation & Setup

1. Run the install script:
   ```bash
   python codex_hooks/install.py
   ```
2. In Codex, review and trust the configured hooks using `/hooks` if prompted.
3. Verify integrity:
   ```bash
   python integrity.py init
   ```
4. Run tests:
   ```bash
   python -m unittest discover -s codex_hooks/tests -v
   ```
