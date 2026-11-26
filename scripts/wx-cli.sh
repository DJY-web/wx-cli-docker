#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
action=${1:-help}
if [ "$#" -gt 0 ]; then shift; fi
case "$action" in
  start)
    if [ ! -f .env ]; then python3 scripts/init-env.py; fi
    exec sh scripts/docker.sh compose up -d wechat
    ;;
  build)
    sh scripts/docker.sh compose --profile cli build wx-cli
    exec sh scripts/docker.sh compose --profile debug build wx-cli-capture
    ;;
  capture)
    desktop=$(sh scripts/docker.sh compose ps -q --status running wechat)
    if [ -z "$desktop" ]; then
      echo "先运行 start 并登录容器微信。捕获需要同意临时调试并手动重新登录。" >&2
      exit 1
    fi
    exec sh scripts/docker.sh compose --profile debug run --rm --no-deps wx-cli-capture
    ;;
  server)
    exec sh scripts/docker.sh compose --profile cli up -d --no-deps wx-cli
    ;;
  run)
    exec sh scripts/docker.sh compose --profile cli run --rm --no-deps --entrypoint wx-cli wx-cli "$@"
    ;;
  stop)
    exec sh scripts/docker.sh compose --profile cli stop wx-cli
    ;;
  *)
    echo "Usage: sh scripts/wx-cli.sh start | build | capture | server | run <args> | stop"
    ;;
esac
