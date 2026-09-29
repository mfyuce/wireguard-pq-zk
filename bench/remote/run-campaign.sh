#!/bin/bash
# Runs a campaign on a test bed on another host until it is complete.
#
#   WGZK_RIG=bench/rigs/NAME.json SSHPASS=... \
#       bench/remote/run-campaign.sh OUT [LIMIT [BLOCKS [TRIALS]]]
#
# LIMIT is the load average (one minute) of the host under the machines above
# which no block is started; default 2. A campaign that stops (load, a lost
# connection) continues after two minutes where it stopped, at most 60 times.
# Everything is written to OUT/campaign.log. The passwords are taken from the
# environment and written nowhere.
set -uo pipefail

OUT="${1:?output directory}"
LIMIT="${2:-2}"
BLOCKS="${3:-10}"
TRIALS="${4:-100}"
: "${WGZK_RIG:?the description of the test bed, bench/rigs/NAME.json}"
: "${SSHPASS:?the password of the user on the host of the test bed}"
cd "$(dirname "$0")/../.."
mkdir -p "$OUT"
LOG="$OUT/campaign.log"
export PYTHONDONTWRITEBYTECODE=1

for attempt in $(seq 1 60); do
    echo "$(date -u +%FT%TZ) attempt $attempt: $BLOCKS blocks of $TRIALS trials on $(basename "$WGZK_RIG" .json), limit $LIMIT" >> "$LOG"
    if python3 bench/campaign.py --out "$OUT" --blocks "$BLOCKS" --trials "$TRIALS" \
            --max-load "$LIMIT" >> "$LOG" 2>&1; then
        echo "$(date -u +%FT%TZ) campaign complete" >> "$LOG"
        exit 0
    fi
    echo "$(date -u +%FT%TZ) stopped; continuing in two minutes" >> "$LOG"
    sleep 120
done
echo "$(date -u +%FT%TZ) gave up after 60 attempts" >> "$LOG"
exit 1
