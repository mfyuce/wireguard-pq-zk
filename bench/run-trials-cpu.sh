#!/bin/bash
# Like run-trials.sh, but also wraps the trial window with perf stat -p <daemon-pid>
# so we get CPU-time attributable to the daemon across N handshakes.
# Usage (inside client VM):  sudo run-trials-cpu.sh N
# Output: JSON lines from [timing] + a final JSON line {"cpu_stats":{...}}.
set -euo pipefail

if [ $# -lt 1 ]; then echo "usage: $0 N" >&2; exit 1; fi
N="$1"
IFACE="wg1l"
SRC_IP="10.10.10.10"
DST_IP="10.20.10.10"
PEER_PUB="$(cat /vagrant/vagrant/keys/public_right)"

DAEMON_PID="$(systemctl show --property MainPID --value wgzk)"
if [ -z "$DAEMON_PID" ] || [ "$DAEMON_PID" = "0" ]; then
    echo "wgzk daemon not running" >&2
    exit 1
fi

LOG_FILE=$(mktemp)
PERF_FILE=$(mktemp)
journalctl -u wgzk -f -o cat --no-pager >"$LOG_FILE" 2>/dev/null &
FOLLOWER=$!
trap 'kill $FOLLOWER 2>/dev/null || true; rm -f "$LOG_FILE" "$PERF_FILE"' EXIT

sleep 0.2

# Estimate the time window the loop will take (≈ 0.2s per trial including sleeps),
# round up to milliseconds, attach perf with --timeout for that window.
TIMEOUT_MS=$((N * 250 + 1000))

perf stat -e task-clock,context-switches,cycles,instructions -p "$DAEMON_PID" \
    --timeout "$TIMEOUT_MS" -o "$PERF_FILE" &
PERF_PID=$!

for i in $(seq 1 "$N"); do
    wg set "$IFACE" peer "$PEER_PUB" remove
    wg set "$IFACE" peer "$PEER_PUB" \
        allowed-ips 10.20.10.0/24 \
        endpoint 192.168.100.1:51921 \
        persistent-keepalive 5
    ping -c 1 -W 2 -I "$SRC_IP" "$DST_IP" >/dev/null 2>&1 || true
    sleep 0.08
done

# Wait for perf to finish its timeout window so it flushes stats
wait "$PERF_PID" 2>/dev/null || true
kill "$FOLLOWER" 2>/dev/null || true
wait "$FOLLOWER" 2>/dev/null || true

# Per-handshake [timing] lines
awk '
/^\[timing\] / {
    token=""; total=""; zk=""; mlkem=""; psk=""; tail="";
    for (i=2; i<=NF; i++) {
        split($i, kv, "=");
        if (kv[1]=="token") token=kv[2];
        else if (kv[1]=="total_us") total=kv[2];
        else if (kv[1]=="zk_us") zk=kv[2];
        else if (kv[1]=="mlkem_us") mlkem=kv[2];
        else if (kv[1]=="psk_us") psk=kv[2];
        else if (kv[1]=="tail_us") tail=kv[2];
    }
    if (token != "") {
        printf "{\"token\":%s,\"total_us\":%s,\"zk_us\":%s,\"mlkem_us\":%s,\"psk_us\":%s,\"tail_us\":%s}\n",
            token, total, zk, mlkem, psk, tail;
    }
}
' "$LOG_FILE"

# Summary CPU line from perf. Cycles/instructions often show "<not counted>"
# inside VirtualBox (no hardware perf counters exposed); normalize to 0.
awk -v n="$N" '
function clean(v) {
    gsub(",", "", v);
    if (v ~ /<not/) return 0;
    return v+0;
}
/msec task-clock/       { task_ms = clean($1); }
/context-switches/      { cs = clean($1); }
/ cycles/               { cyc = clean($1); }
/instructions/          { ins = clean($1); }
END {
    printf "{\"cpu_summary\":{\"n\":%s,\"task_ms\":%.4f,\"context_switches\":%d,\"cycles\":%d,\"instructions\":%d}}\n",
        n, task_ms, cs, cyc, ins;
}
' "$PERF_FILE"
