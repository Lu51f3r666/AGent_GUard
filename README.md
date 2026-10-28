# AgentGuard — Codex Hook + Integrity Starter

This is a **prototype for the assigned Codex Hook System and Integrity System tasks**. It is not the complete AgentGuard pipeline: intent extraction, ML anomaly detection, and the LLM intent judge are not implemented here.

## What is included

- `PreToolUse` adapter: reads the event JSON from stdin, checks integrity, normalizes a supported tool action, applies deterministic rules, and returns Codex's documented deny response when a rule blocks an action.
- `PostToolUse` adapter: writes a small audit record after a tool call.
- Integrity checker: SHA-256 checks a manifest of the hook and policy files before the pre-tool policy runs.
- Minimal tests for representative policy decisions.

## Requirements

- Python 3.10+ (uses only the Python standard library).
- A Codex version/platform where command hooks are enabled.
- A trusted project directory. Codex may require reviewing/trusting non-managed hooks in `/hooks`.

## Setup

1. Install the Codex hook configuration:
   ```bash
   python codex_hooks/install.py
   ```
2. Review `.codex/hooks.json` or `codex_hooks/hooks.json` to verify paths.
3. Initialize the integrity manifest from the repository root:

   ```bash
   python integrity.py init
   ```

4. Review configured hooks using `/hooks` in Codex if prompted.
5. Run the test suites:

   ```bash
   # Run Codex hook tests
   python -m unittest discover -s codex_hooks/tests -v

   # Run all repository tests
   python -m unittest discover -s . -p "test_*.py" -v
   ```

7. Test only in a disposable repository. First try a harmless command such as `python --version`; then verify that a test event targeting a sensitive path is denied by the policy.

## Important implementation notes

- Codex hook input is one JSON object on stdin. `tool_input` differs by tool; do not assume every tool uses the same fields.
- `PreToolUse` coverage is **not a complete security boundary**. The current hook path may not intercept every way an agent can perform an equivalent operation. Keep ordinary OS permissions and sandboxing enabled.
- This sample uses deterministic rules only. It does not claim to infer the user's full intent.
- The four-way project decision model (`ALLOW`, `REQUIRE APPROVAL`, `BLOCK`, `ESCALATE`) is not fully mapped here. This adapter implements allow/block and logs. Codex's currently supported hook response semantics may not support an interactive approval decision from a command hook.
- The integrity manifest detects changes relative to the manifest. If an attacker can modify both the protected files **and** the manifest, a local hash manifest alone cannot prove authenticity. For stronger integrity, keep a signed manifest or expected digest in a separately protected location.
- Fail-closed behavior is configured for missing/invalid integrity manifest: the pre-tool hook denies the supported tool call. Verify behavior on your Codex version before relying on it.
- Logs are local JSONL files under `.codex/agentguard/logs/`. Do not log raw prompts or complete tool inputs by default.

## Architecture

```text
Codex tool request
       |
       v
PreToolUse hook script
       |
       +--> Integrity verification (manifest + SHA-256)
       |
       +--> Normalize tool event
       |
       +--> Deterministic policy rules
       |
       +--> ALLOW (exit normally) or BLOCK (hookSpecificOutput.permissionDecision=deny)
       |
       v
Codex proceeds only if the call is not denied and other permissions allow it
       |
       v
PostToolUse hook --> audit record
```

## Next steps for the full project

1. Define a stable `NormalizedAction` schema shared across adapters.
2. Add expected-tool-set comparison based on task intent.
3. Add an ML anomaly/context-risk model over normalized features and session history.
4. Add an LLM intent judge only for unresolved actions.
5. Add a decision engine and a tested mapping from project decisions to the host agent's supported responses.
6. Add integration tests using real Codex-generated event payloads from the installed version.
