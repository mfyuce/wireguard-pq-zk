#!/bin/bash
# Host-side driver: switches variant on client (and if applicable gateway),
# runs N trials, pulls results.
#
# Usage:  bench/host-driver.sh {zk-only|zk-pq} <N> <output.jsonl>
set -euo pipefail

if [ $# -lt 3 ]; then
    echo "usage: $0 {zk-only|zk-pq} N OUT" >&2
    exit 1
fi
VARIANT="$1"
N="$2"
OUT="$3"

cd "$(dirname "$0")/.."

# Switch both sides (gateway too — ZK-only means gateway listener is disabled)
vagrant ssh gateway -c "sudo /vagrant/bench/variant-switch.sh $VARIANT" 2>&1 | tail -2
vagrant ssh client  -c "sudo /vagrant/bench/variant-switch.sh $VARIANT" 2>&1 | tail -2

# Let the daemons settle after restart
sleep 1

# Trigger trials on client; capture to file
vagrant ssh client -c "sudo /vagrant/bench/run-trials-cpu.sh $N" > "$OUT" 2>/dev/null

echo "==> variant=$VARIANT trials captured: $(wc -l <"$OUT") lines → $OUT"
python3 bench/analyze.py "$VARIANT" "$OUT"
