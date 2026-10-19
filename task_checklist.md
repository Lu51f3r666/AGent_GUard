# Assigned Task Checklist

## Codex Hook System
- [x] Sample hook configuration for `PreToolUse` and `PostToolUse`.
- [x] Parse Codex JSON input from stdin.
- [x] Normalize tool name, action category, target, and IDs.
- [x] Connect the hook to a deterministic AgentGuard policy function.
- [x] Emit a documented `PreToolUse` deny response for blocked actions.
- [x] Log pre-tool decisions and post-tool completion metadata.
- [ ] Verify the event payload and denial behavior against the exact Codex build/platform used by the team.
- [ ] Merge the sample hook config with the team's existing Codex config and review/trust it in `/hooks`.

## Integrity System
- [x] SHA-256 baseline generation.
- [x] Verify hook and policy file hashes before policy evaluation.
- [x] Fail closed if the manifest is missing, invalid, or a protected file changed.
- [ ] Store a signed/externally protected baseline if the threat model includes an attacker who can edit the project directory.
- [ ] Add integration tests and decide whether logs need tamper-evident chaining or remote storage.

## Not implemented in this starter
- Intent extraction from the user's task.
- Expected-tool-set check.
- ML anomaly/context-risk model.
- LLM intent judge.
- Full four-way decision engine (`ALLOW`, `REQUIRE APPROVAL`, `BLOCK`, `ESCALATE`).
- A claim of complete mediation over every possible Codex action.
