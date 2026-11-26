#!/usr/bin/env python3
"""Check tracked/staged files without printing secret values or touching accounts."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_PARTS = {"data", "backups", "__pycache__", ".venv", "private", ".capture", "target", "dist"}
PRIVATE_NAMES = {"keys.toml", "api-token", "admin-password", "bridge-token", "Cookies", "Login Data"}
SECRET_PATTERNS = [
    re.compile(rb"(?m)^-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----$"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
]


def main():
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().strip("\0").split("\0")
    errors = []
    count = 0
    for name in filter(None, paths):
        path = Path(name)
        count += 1
        if (
            PRIVATE_PARTS.intersection(path.parts)
            or path.name in PRIVATE_NAMES
            or (path.name.startswith(".env") and path.name != ".env.example")
            or path.suffix in {".log", ".pid", ".sqlite3", ".db", ".pem", ".key", ".pyc"}
            or ".git" in path.parts
        ):
            errors.append(f"runtime/private file: {name}")
            continue
        data = subprocess.check_output(["git", "show", ":" + name], cwd=ROOT)
        if any(pattern.search(data) for pattern in SECRET_PATTERNS):
            errors.append(f"credential pattern: {name}")
    if errors:
        print("Release check failed (values suppressed):", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Release check passed: {count} tracked files; no runtime/private paths or credential patterns.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
