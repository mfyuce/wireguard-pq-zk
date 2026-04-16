#!/bin/bash
# Drive N handshake trials on a stock WireGuard interface (wg0b created by
# baseline-swap.sh) and emit per-trial first-ping RTT in microseconds.
#
# Rationale: stock WireGuard has no NEED_PROOF event, so we can't use the
# daemon-emitted [timing] line. First-ping RTT after `wg set peer ... remove; add`
# forces a Noise handshake and delays the ICMP reply until the handshake
# completes. Subtracting steady-state idle-ping RTT gives an approximate
# handshake time comparable to the 0.41 ms cited from the WireGuard literature.
#
# Usage (inside client VM, after baseline-swap.sh stock left):  sudo run-trials-baseline.sh N
set -euo pipefail

if [ $# -lt 1 ]; then echo "usage: $0 N" >&2; exit 1; fi
N="$1"
IFACE="wg0b"
SRC_IP="10.10.10.10"
DST_IP="10.20.10.10"
PEER_PUB="$(cat /vagrant/vagrant/keys/public_right)"

for i in $(seq 1 "$N"); do
    wg set "$IFACE" peer "$PEER_PUB" remove >/dev/null 2>&1 || true
    wg set "$IFACE" peer "$PEER_PUB" \
        endpoint 192.168.100.1:51921 \
        allowed-ips 10.20.10.0/24
    t_start=$(date +%s%N)
    out=$(ping -c 1 -W 2 -I "$SRC_IP" "$DST_IP" 2>/dev/null || true)
    t_end=$(date +%s%N)
    rtt_us=$(( (t_end - t_start) / 1000 ))
    # Also parse ping's reported RTT (steady-state round-trip of the single echo)
    ping_rtt_ms=$(echo "$out" | awk -F'time=' '/time=/ {split($2,a," "); print a[1]; exit}')
    ping_rtt_us=$(awk -v x="$ping_rtt_ms" 'BEGIN{printf "%d", x*1000}' 2>/dev/null)
    : "${ping_rtt_us:=0}"
    printf '{"i":%d,"rtt_us":%d,"ping_rtt_us":%d}\n' "$i" "$rtt_us" "$ping_rtt_us"
    sleep 0.12
done
