# Claude Code Hooks

This folder connects AGent_GUard to Claude Code. Claude Code runs `hook.py`
every time something happens in a session (a prompt, a tool call, a subagent,
...). The hook passes each event to our pipeline, and the pipeline decides
whether a tool call should go ahead, ask the user, or be blocked.

Python 3 standard library only. Linux/macOS.

## Workflow

For every event:

1. **Receive:** Claude Code sends the event to `hook.py` as JSON on stdin.
2. **Normalize:** `hook.py` turns it into one standard event format.
3. **Remember:** on a new prompt, the task text is saved in
   `data/state/<session>.json` so the pipeline knows what the user asked for.
4. **Decide:** the event is passed to the pipeline's `handle(event)`, which
   returns `silent`, `ask` or `deny` with a reason.
5. **Log:** one JSON line is appended to `data/events.jsonl`.
6. **Enforce (PreToolUse only):** this is where AGent_GUard acts. Our
   pipeline's verdict is sent to Claude Code, which must follow it:
   - `deny`: the tool call is blocked and our reason is shown
   - `ask`: the user must confirm before it runs
   - `silent`: we have no objection; Claude Code's own permission rules then
     apply as usual

The hook never returns `allow`, so it can only make Claude Code stricter.
If the hook or pipeline fails, it stays silent, or denies when
`FAIL_CLOSED = True` in `config.py`.

## Events used

| Claude Code event | Normalized name | When it fires |
|---|---|---|
| SessionStart | `session_start` | A session starts or resumes |
| UserPromptSubmit | `prompt_submit` | The user sends a prompt |
| PreToolUse | `pre_tool` | Before a tool runs. **Our pipeline decides here (ask/deny).** |
| PostToolUse | `post_tool` | After a tool succeeds |
| PostToolUseFailure | `post_tool_failure` | After a tool fails |
| PermissionRequest | `permission_request` | Claude Code shows a permission prompt |
| PermissionDenied | `permission_denied` | A tool call is refused |
| SubagentStart | `subagent_start` | A subagent starts |
| SubagentStop | `subagent_stop` | A subagent finishes |
| Stop | `stop` | Claude finishes its reply |
| SessionEnd | `session_end` | The session ends |
| ConfigChange | `config_change` | Settings change during the session |

All other events are observe-only: they give the pipeline context (the task,
tool results, subagents, ...) but can't change anything.

## How to run

```bash
cd claude_code_hooks

python3 install.py --dry-run    # preview the change to ~/.claude/settings.json
python3 install.py              # register the hooks (backs up settings.json first)
python3 install.py --uninstall  # remove our hooks only
```

Then start a new Claude Code session and watch the events arrive:

```bash
tail -f data/events.jsonl
```

To try blocking, set `PIPELINE_MODULE = "demo_pipeline"` in `config.py`. It
denies access to `test_secret.txt` and asks before touching `.env`.

Notes:
- The hooks run `hook.py` from this folder, so don't move the folder after
  installing (or run `install.py` again).
- If your pipeline needs packages from a venv, install with
  `python3 install.py --python /path/to/venv/bin/python`.

## Settings (`config.py`)

| Setting | Meaning |
|---|---|
| `PIPELINE_MODULE` | Which pipeline to use (`pipeline_stub` by default, which is always silent). |
| `PIPELINE_MODE` | `module` (import and call it) or `http` (POST the event to `PIPELINE_URL`). |
| `LOG_ONLY` | Log the pipeline's verdicts without ever asking or blocking. |
| `FAIL_CLOSED` | Block tool calls if the hook or pipeline fails. |
| `LOG_PATH`, `STATE_DIR` | Where to write the log and session state (default: `data/`). |

## Writing a pipeline

Replace `pipeline_stub.py` with a module that has:

```python
def handle(event: dict) -> dict:
    return {"verdict": "silent", "reason": ""}   # or "ask" / "deny"
```

To read the saved task for the session:

```python
from hook import get_session_state
get_session_state(event["session_id"])   # {"task", "run_tag", "prompts", "updated"}
```

## Tests

```bash
cd claude_code_hooks && python3 -B -m unittest discover -s tests -v
```

The tests use a temporary home folder, so your real settings are never touched.
