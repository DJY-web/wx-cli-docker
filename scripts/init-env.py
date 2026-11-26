#!/usr/bin/env python3
"""Generate local desktop credentials without printing them."""
import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parent.parent / ".env"
if path.exists():
    raise SystemExit(".env 已存在，未覆盖。")
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("COMPOSE_PROJECT_NAME=wx-cli-docker\nWECHAT_USER=operator\n")
    f.write("WECHAT_PASSWORD=wx_" + secrets.token_urlsafe(24) + "\nTZ=Asia/Tokyo\n")
print("已生成私有 .env；桌面访问口令保存在该文件中。")
