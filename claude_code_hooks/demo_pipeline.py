def handle(event):
    if event["event"] != "pre_tool":
        return {"verdict": "silent", "reason": ""}
    ti = event.get("tool_input") or {}
    target = str(ti.get("command") or ti.get("file_path") or "")
    if "test_secret.txt" in target:
        return {"verdict": "deny", "reason": "demo: test_secret.txt is off limits"}
    if ".env" in target:
        return {"verdict": "ask", "reason": "demo: .env may hold secrets"}
    return {"verdict": "silent", "reason": ""}