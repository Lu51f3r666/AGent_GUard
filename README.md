# Agent_Guard

An intent-aware security monitor for AI coding agents. It checks every action
the agent tries **before it runs**, compares it with the user's task and
normal behavior, and stays silent, asks a human, or blocks it with a reason.
The first supported agent is Claude Code.

## Files

| Path | What it is |
|---|---|
| `claude_code_hooks/` | The Claude Code integration. See [`ClaudeHooks.md`](claude_code_hooks/ClaudeHooks.md). |
| `claude_code_hooks/ClaudeHooks.md` | How the hooks work, how to run them, and the events they use. |
| `claude_code_hooks/hook.py` | The script Claude Code runs for every event. |
| `claude_code_hooks/install.py` | Adds or removes our hooks in `~/.claude/settings.json`. |
| `claude_code_hooks/config.py` | Settings: which pipeline, log-only mode, fail-closed mode, log limits. |
| `claude_code_hooks/pipeline_stub.py` | Placeholder pipeline (always silent), to be replaced by the real one. |
| `claude_code_hooks/data/` | Logs and session state, created when the hook runs (not in git). |
