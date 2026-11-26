#!/usr/bin/env python3
"""Local agent example: load token in memory, print only the requested API result."""
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import Request, urlopen

root = Path(__file__).resolve().parent.parent
path = sys.argv[1] if len(sys.argv) > 1 else "/api/v1/health"
if not path.startswith("/api/v1/"):
    raise SystemExit("Use a relative /api/v1/... endpoint.")
token = subprocess.check_output(
    ["sh", "scripts/docker.sh", "compose", "--profile", "cli", "exec", "-T", "wx-cli", "cat", "/state/config/wx-cli/api-token"],
    cwd=root, text=True, stderr=subprocess.DEVNULL,
).strip()
request = Request("http://127.0.0.1:9100" + path, headers={"Authorization": "Bearer " + token})
with urlopen(request, timeout=30) as response:
    print(json.dumps(json.load(response), ensure_ascii=False, indent=2))
