#!/bin/bash
# End-to-end test on the CLIENT VM: two connections, each with its own key.
# Pings the tunnel address of the gateway; the first packet of a connection
# triggers the handshake.
set -euo pipefail

IFACE="wg1l"
GW_ADDR="fd57:475a:4b00::1"

session() {
    wg show "$IFACE" public-key
    ip -6 -o addr show dev "$IFACE" scope global | awk '{print $4}'
}

fail() {
    echo "TEST FAILED: $*"
    echo "── Client daemon log ────────────────────────────────"
    journalctl -u wgzk --no-pager -n 30
    exit 1
}

echo ""
echo "══════════════════════════════════════════════════════"
echo "  wgzk protocol R1: end-to-end test"
echo "══════════════════════════════════════════════════════"
sleep 3   # let the daemons settle

echo "── Connection 1 ─────────────────────────────────────"
FIRST="$(session)"
echo "$FIRST"
ping -6 -c 5 -W 5 "$GW_ADDR" || fail "no reply on connection 1"

echo "── Connection 2 (new key, new address) ──────────────"
wg-zk-daemon new-connection --iface "$IFACE"
SECOND="$(session)"
echo "$SECOND"
[ "$FIRST" != "$SECOND" ] || fail "key and address did not change"
ping -6 -c 5 -W 5 "$GW_ADDR" || fail "no reply on connection 2"

echo "── Client daemon log ────────────────────────────────"
journalctl -u wgzk --no-pager -n 20
echo "── WireGuard status ─────────────────────────────────"
wg show "$IFACE"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  TEST PASSED"
echo "══════════════════════════════════════════════════════"
