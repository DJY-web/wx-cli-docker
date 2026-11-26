#!/bin/sh
# Compatibility entry point for the unified Docker project.
set -eu
exec sh "$(dirname "$0")/../../scripts/wx-cli.sh" "$@"
