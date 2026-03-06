import json
import os
from datetime import datetime, timezone
from typing import Optional

def log_raw_response(
    protocol: str,          # "snmp" or "ssh"
    host: str,
    command: str,
    raw_output: str = "",
    success: bool = True,
    error: Optional[str] = None,
    truncate: int = 20000   # Optional: truncate huge outputs (e.g. show run)
):
    log_dir = "out/logs/responses"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    safe_cmd = command.replace(" ", "-").replace("/", "_").replace("\\", "_")[:50]
    filename = f"{protocol}-{host}-{timestamp}-{safe_cmd}.json"

    # Truncate very large outputs to avoid massive files
    if len(raw_output) > truncate:
        raw_output = raw_output[:truncate] + "\n... [truncated - original length: {} chars]".format(len(raw_output))

    data = {
        "timestamp": timestamp,
        "host": host,
        "command": command,
        "raw_output": raw_output,
        "success": success,
        "error": error or None,
        "output_length": len(raw_output)
    }

    path = os.path.join(log_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[LOGGED RAW] {protocol.upper()} response saved: {path}")