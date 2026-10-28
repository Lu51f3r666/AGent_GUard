# Antigravity IDE Hooks for AgentGuard

This package connects **AgentGuard** to **Antigravity IDE** (and the Antigravity Agent runtime).

Antigravity IDE triggers lifecycle hooks before and after tool execution. The hook script passes each event to our AgentGuard pipeline, which inspects the proposed action against deterministic security rules, integrity baseline verification, and session taint tracking.

---

## Architecture and Flow

```text
Antigravity IDE
       |
       v (stdin: JSON with toolCall, stepIdx, conversationId)
antigravity_hooks/hook.py
       |
       +--> Verify Integrity (SHA-256 self-check)
       +--> Normalize Antigravity tools (run_command, write_to_file, view_file, ...)
       +--> Evaluate Security Rules (AgentGuard policy engine)
       |
       v (stdout: JSON response)
Decision returned to Antigravity IDE:
  - "allow"   --> Tool proceeds
  - "ask"     --> User prompted for confirmation
  - "deny"    --> Tool immediately blocked
```

---

## Supported Antigravity Tools Mapping

| Antigravity Tool | Target Argument | Action Type | Default Policy Action |
|---|---|---|---|
| `run_command` | `CommandLine` | `EXECUTE` | Block destructive commands (`rm -rf /`, `shutdown`, reverse shells); alert on egress after sensitive reads. |
| `write_to_file` | `TargetFile` | `WRITE` | Deny writes to protected AgentGuard files (tamper prevention). |
| `replace_file_content` | `TargetFile` | `WRITE` | Deny writes to protected AgentGuard files. |
| `multi_replace_file_content` | `TargetFile` | `WRITE` | Deny writes to protected AgentGuard files. |
| `view_file` | `AbsolutePath` | `READ` | Deny private SSH keys & credentials; ask on `.env` configuration. |
| `list_dir` / `grep_search` | `DirectoryPath` / `SearchPath` | `READ` | Gated on sensitive path fragments. |
| `read_url_content` / `search_web` | `Url` / `query` | `NETWORK` | Taint tracking alert if preceded by reading `.env`. |

---

## Workspace Setup (`.agents/hooks.json`)

Antigravity IDE automatically discovers hooks placed in `.agents/hooks.json` at the workspace root:

```json
{
  "agentguard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python antigravity_hooks/hook.py",
            "timeout": 15
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python antigravity_hooks/hook.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

---

## Testing

Run the Antigravity hook unit tests:
```bash
python -m unittest discover -s antigravity_hooks/tests -v
```

Run all tests across the repository:
```bash
python -m unittest discover -s . -p "test_*.py" -v
```
