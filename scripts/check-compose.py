#!/usr/bin/env python3
"""Validate real Compose configuration; never starts services or reads account data."""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
env = {**os.environ, "WECHAT_PASSWORD": "configuration-check-only"}
base = ["sh", "scripts/docker.sh", "compose", "--env-file", ".env.example"]
result = subprocess.check_output(base + ["--profile", "cli", "--profile", "debug", "config", "--format", "json"], cwd=root, env=env, text=True)
config = json.loads(result)
services = config["services"]
assert set(services) == {"wechat", "wx-cli", "wx-cli-capture"}
assert services["wx-cli-capture"]["pid"] == "service:wechat"
assert services["wx-cli-capture"]["network_mode"] == "none"
assert "SYS_PTRACE" not in services["wx-cli"].get("cap_add", [])
assert services["wx-cli"]["cap_drop"] == ["ALL"]
assert services["wx-cli"]["read_only"]
assert any(v["source"] == "wechat-config" and v["read_only"] for v in services["wx-cli"]["volumes"])
assert all(p["host_ip"] == "127.0.0.1" for s in services.values() for p in s.get("ports", []))
subprocess.run(base + ["-f", "compose.yaml", "-f", "compose.wechat-build.yaml", "config", "--quiet"], cwd=root, env=env, check=True)
print("Compose integration passed: scoped desktop, read-only CLI, explicit capture and localhost ports.")
