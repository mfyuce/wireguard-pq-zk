#!/bin/bash
# Runs a campaign while the host is quiet and waits while it is not.
#
#   bench/when-quiet.sh OUT [LIMIT [BLOCKS [TRIALS]]]
#
# LIMIT is the load average of the host (one minute) above which no block is
# started; default 4. The campaign continues where it stopped, so the script
# can be interrupted and started again. Everything is written to OUT/campaign.log.
set -uo pipefail

OUT="${1:?output directory}"
LIMIT="${2:-4}"
BLOCKS="${3:-10}"
TRIALS="${4:-100}"
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
LOG="$OUT/campaign.log"

quiet() {
    awk -v limit="$LIMIT" '{ exit !($1 <= limit) }' /proc/loadavg
}

echo "$(date -u +%FT%TZ) waiting for a load of $LIMIT or less; $BLOCKS blocks of $TRIALS trials" >> "$LOG"
while :; do
    # Three quiet minutes in a row before a start, so that a short pause of
    # other work does not count as a quiet host.
    calm=0
    while [ "$calm" -lt 3 ]; do
        if quiet; then calm=$((calm + 1)); else calm=0; fi
        sleep 60
    done
    echo "$(date -u +%FT%TZ) quiet, load $(cut -d' ' -f1 /proc/loadavg): starting or continuing" >> "$LOG"
    if python3 bench/campaign.py --out "$OUT" --blocks "$BLOCKS" --trials "$TRIALS" \
            --max-load "$LIMIT" >> "$LOG" 2>&1; then
        echo "$(date -u +%FT%TZ) campaign complete" >> "$LOG"
        exit 0
    fi
    echo "$(date -u +%FT%TZ) stopped, load $(cut -d' ' -f1 /proc/loadavg); waiting again" >> "$LOG"
done
