"""Configuration for the Claude Code hooks."""

# If our code or the pipeline fails during PreToolUse: False = stay silent
# (normal permission flow), True = deny the call.
FAIL_CLOSED = False

# Pass events to the pipeline and log them, but never return ask or deny.
LOG_ONLY = False

# How the pipeline is reached: "module" imports PIPELINE_MODULE and calls its
# handle(); "http" POSTs the event JSON to PIPELINE_URL and reads the same response.
PIPELINE_MODE = "module"
PIPELINE_MODULE = "pipeline_stub"
PIPELINE_URL = "http://127.0.0.1:8765/handle"
PIPELINE_TIMEOUT = 3.0  # seconds, http mode; keep well under the 10 s hook timeout

# Log and state locations; None = data/events.jsonl and data/state/ in this folder.
LOG_PATH = None
STATE_DIR = None

# Long strings in the log are cut to this many characters; long lists to this many items.
MAX_LOG_STRING = 2000
MAX_LOG_ITEMS = 200

# Task text kept in per-session state is cut to this many characters.
MAX_TASK_CHARS = 20000
