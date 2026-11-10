#!/bin/sh
#
# pager-ui: show what the daemon has seen on the Pager's screen.
#
# This is what the Pager's payload menu runs. It does nothing but call the
# plugin's binary and hand the answer to `logger`, which is how the Pager
# shows a line on its screen.
#
# The binary is here because the Pager's busybox has no `nc -U` and no JSON
# parser: a shell script cannot speak to the daemon's Unix socket.
#
# It only reads. It never touches a radio, a channel or a service.

BIN="$(dirname "$0")/bin/pager-ui"

if [ ! -x "$BIN" ]; then
    logger -t payload "pager-ui: $BIN is missing"
    exit 1
fi

OUTPUT="$("$BIN" 2>&1)" || {
    logger -t payload "pager-ui: $OUTPUT"
    exit 1
}

# One logger call per line, so the screen shows them as separate lines.
echo "$OUTPUT" | while IFS= read -r line; do
    [ -n "$line" ] && logger -t payload "$line"
done
