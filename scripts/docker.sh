#!/bin/sh
# Use Docker Desktop's bundled CLI if no system-wide link is installed.
set -eu
if command -v docker >/dev/null 2>&1; then
  exec docker "$@"
fi
docker_bin=/Applications/Docker.app/Contents/Resources/bin/docker
if [ ! -x "$docker_bin" ]; then
  echo "未找到 Docker Desktop，请先安装并启动。" >&2
  exit 1
fi
PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
export PATH
exec "$docker_bin" "$@"
