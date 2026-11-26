#!/bin/sh
set -eu
umask 077
mkdir -p /state/config/wx-cli
token_file=/state/config/wx-cli/api-token
if [ ! -s "$token_file" ]; then
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$token_file"
fi
exec wx-cli server foreground --host 0.0.0.0 --port 9100 --token "$(cat "$token_file")" --poll --poll-ms 1000
