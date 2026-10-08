#!/bin/sh
# Verify one AEE statement. Usage: ./run.sh <statement.json>
# Optional consumer key policy: AEE_SUBSTRATE_KEYS=/path/keys.json ./run.sh <statement.json>
exec python3 "$(dirname "$0")/aee_verify.py" "$@"
