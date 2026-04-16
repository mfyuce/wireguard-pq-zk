#!/bin/bash
# Drive N handshake trials on the client VM and emit per-trial daemon timings.
# Usage (inside client VM):  sudo run-trials.sh N
# Output: JSON lines from the daemon's [timing] log entries.
set -euo pipefail

if [ $# -lt 1 ]; then echo "usage: $0 N" >&2; exit 1; fi
N="$1"
IFACE="wg1l"
SRC_IP="10.10.10.10"
DST_IP="10.20.10.10"
PEER_PUB="$(cat /vagrant/vagrant/keys/public_right)"

# Follow journal → tempfile so we capture every [timing] line emitted during trials
LOG_FILE=$(mktemp)
journalctl -u wgzk -f -o cat --no-pager >"$LOG_FILE" 2>/dev/null &
FOLLOWER=$!
trap 'kill $FOLLOWER 2>/dev/null || true; rm -f "$LOG_FILE"' EXIT

sleep 0.2

for i in $(seq 1 "$N"); do
    wg set "$IFACE" peer "$PEER_PUB" remove
    wg set "$IFACE" peer "$PEER_PUB" \
        allowed-ips 10.20.10.0/24 \
        endpoint 192.168.100.1:51921 \
        persistent-keepalive 5
    ping -c 1 -W 2 -I "$SRC_IP" "$DST_IP" >/dev/null 2>&1 || true
    sleep 0.08
done

sleep 0.4
kill $FOLLOWER 2>/dev/null || true
wait $FOLLOWER 2>/dev/null || true

awk '
/^\[timing\] / {
    token=""; total=""; zk=""; mlkem=""; psk=""; tail="";
    for (i=2; i<=NF; i++) {
        split($i, kv, "=");
        if (kv[1]=="token")     token=kv[2];
        else if (kv[1]=="total_us") total=kv[2];
        else if (kv[1]=="zk_us")    zk=kv[2];
        else if (kv[1]=="mlkem_us") mlkem=kv[2];
        else if (kv[1]=="psk_us")   psk=kv[2];
        else if (kv[1]=="tail_us")  tail=kv[2];
    }
    if (token != "") {
        printf "{\"token\":%s,\"total_us\":%s,\"zk_us\":%s,\"mlkem_us\":%s,\"psk_us\":%s,\"tail_us\":%s}\n",
            token, total, zk, mlkem, psk, tail;
    }
}
' "$LOG_FILE"
