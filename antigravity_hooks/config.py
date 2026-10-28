"""Configuration for Antigravity IDE Hooks."""

# If our code or the pipeline fails during PreToolUse: False = allow, True = deny
FAIL_CLOSED = True

# Pass events to the pipeline and log them, but never block
LOG_ONLY = False

# How the pipeline is reached: "module" imports PIPELINE_MODULE and calls handle()
PIPELINE_MODE = "module"
PIPELINE_MODULE = "agentguard_pipeline"

# Log and state locations; None = data/events.jsonl and data/state/ in this folder.
LOG_PATH = None
STATE_DIR = None

# Log limits
MAX_LOG_STRING = 2000
MAX_LOG_ITEMS = 200

# Task text limit in per-session state
MAX_TASK_CHARS = 20000
