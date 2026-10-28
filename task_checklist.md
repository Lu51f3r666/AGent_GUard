# Assigned Task Checklist

## Codex Hook System (`codex_hooks/`)
- [x] Dedicated modular package (`codex_hooks/` with `pre_tool_use.py`, `post_tool_use.py`, `hook.py`).
- [x] Sample hook configuration for `PreToolUse` and `PostToolUse` (`codex_hooks/hooks.json`).
- [x] Parse Codex JSON input from stdin.
- [x] Normalize tool name, action category, target, and IDs.
- [x] Connect the hook to a deterministic AgentGuard policy function.
- [x] Emit a documented `PreToolUse` deny response for blocked actions.
- [x] Log pre-tool decisions and post-tool completion metadata (`codex_hooks/logs/`).
- [x] Dedicated Codex hook unit test suite (`codex_hooks/tests/`).
- [x] Installation and setup helper script (`codex_hooks/install.py`).
- [ ] Verify the event payload and denial behavior against the exact Codex build/platform used by the team.
- [ ] Merge the sample hook config with the team's existing Codex config and review/trust it in `/hooks`.

## Claude Code Hook System
- [x] Implement unified 12-event hook receiver (`claude_code_hooks/hook.py`).
- [x] Implement real AgentGuard pipeline (`claude_code_hooks/agentguard_pipeline.py`).
- [x] Fail-closed enforcement on security violations and self-check failure.
- [x] Full 3-way verdict rendering (`silent` / allow, `ask` / human confirm, `deny` / block).
- [x] Task contract capture on `UserPromptSubmit` (`prompt_submit`).
- [x] Tamper prevention protecting all security files from modification.
- [x] Taint tracking for network egress following sensitive config reads.
- [x] Unit test suite for hook events and pipeline decisions (`claude_code_hooks/tests/`).

## Antigravity IDE Hook System
- [x] Implement lifecycle hook adapter (`antigravity_hooks/hook.py`).
- [x] Workspace hook configuration discovered via `.agents/hooks.json`.
- [x] Normalize Antigravity IDE tools (`run_command`, `write_to_file`, `view_file`, `list_dir`, `read_url_content`, etc.).
- [x] Implement real pipeline (`antigravity_hooks/agentguard_pipeline.py`) integrated with AgentGuard core.
- [x] Support Antigravity protocol responses (`decision`: `allow`, `ask`, `deny`).
- [x] Full unit test suite (`antigravity_hooks/tests/`).
- [x] Installer and management script (`antigravity_hooks/install.py`).


## Integrity System
- [x] SHA-256 baseline generation.
- [x] Verify hook and policy file hashes before policy evaluation across Codex and Claude Code.
- [x] Fail closed if the manifest is missing, invalid, or a protected file changed.
- [x] Comprehensive integration test suite (`test_integration.py`).
- [ ] Store a signed/externally protected baseline if the threat model includes an attacker who can edit the project directory.

## Layer 1: Behavioral & Contextual Security
- [x] Task Contract Scope Extraction (`extract_task_scope`) parsing allowed files from prompts.
- [x] Target-Binding Enforcement: Gates state-changing file edits to out-of-scope targets.
- [x] Session Denial Thresholds & Freezing: Freezes session upon 3 consecutive (or 20 total) denials and escalates to human.
- [x] Fast Path for pure in-project safe reads to avoid IDE latency.
- [x] Cryptographic Hash-Chained Audit Log (`build_audit_entry`, `verify_audit_chain`) with SHA-256 tamper evidence.
- [x] Session Taint Tracking for network egress following sensitive config reads.

## Not implemented in this starter
- ML anomaly/context-risk model over tool sequences.
- Layer 2 LLM intent judge (independent judge model on escalation).
- Remote telemetry export (Slack / OpenTelemetry).

