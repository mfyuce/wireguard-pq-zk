#!/bin/bash
# Swap the loaded `wireguard` module between our patched wgzk build (under
# /lib/modules/.../extra/) and the upstream in-tree build (under /kernel/...).
# Takes down wg1l (wgzk) and brings up wg0b (stock) or vice-versa.
#
# Usage:  sudo baseline-swap.sh {stock|wgzk} <side>
#          side = left|right  (left = client, right = gateway)
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 [stock|wgzk] [left|right]" >&2
    exit 1
fi
MODE="$1"
SIDE="$2"

KERNEL_REL="$(uname -r)"
UPSTREAM_MOD="/lib/modules/${KERNEL_REL}/kernel/drivers/net/wireguard/wireguard.ko"
WGZK_MOD="/lib/modules/${KERNEL_REL}/extra/wireguard.ko"

KEYS=/vagrant/vagrant/keys
case "$SIDE" in
    left)
        PRIV="$(cat $KEYS/private_left)"
        PEER_PUB="$(cat $KEYS/public_right)"
        LISTEN=51821
        ADDR="10.10.10.10/24"
        ENDPOINT="192.168.100.1:51921"
        ALLOWED="10.20.10.0/24"
        ;;
    right)
        PRIV="$(cat $KEYS/private_right)"
        PEER_PUB="$(cat $KEYS/public_left)"
        LISTEN=51921
        ADDR="10.20.10.10/24"
        ENDPOINT=""
        ALLOWED="10.10.10.0/24"
        ;;
    *)
        echo "bad side: $SIDE" >&2; exit 1 ;;
esac

tear_down() {
    systemctl stop wgzk 2>/dev/null || true
    ip link delete wg1l 2>/dev/null || true
    ip link delete wg0b 2>/dev/null || true
    rmmod wireguard 2>/dev/null || true
}

bring_up_stock() {
    insmod "$UPSTREAM_MOD"
    ip link add dev wg0b type wireguard
    ip addr add "$ADDR" dev wg0b
    ip link set wg0b up
    wg set wg0b listen-port "$LISTEN" private-key <(echo "$PRIV")
    if [ -n "$ENDPOINT" ]; then
        wg set wg0b peer "$PEER_PUB" \
            endpoint "$ENDPOINT" \
            allowed-ips "$ALLOWED"
    else
        wg set wg0b peer "$PEER_PUB" \
            allowed-ips "$ALLOWED"
    fi
    echo "==> wg0b (stock) up on side=$SIDE"
}

bring_up_wgzk() {
    insmod "$WGZK_MOD"
    # wgzk daemon + its configuration is provisioned by 03-client.sh / 03-gateway.sh.
    # Re-run the provisioner fragment that creates wg1l.
    if [ "$SIDE" = "left" ]; then
        bash /vagrant/vagrant/03-client.sh >/dev/null 2>&1 || true
    else
        bash /vagrant/vagrant/03-gateway.sh >/dev/null 2>&1 || true
    fi
    systemctl restart wgzk
    sleep 0.5
    echo "==> wg1l (wgzk) up on side=$SIDE"
}

case "$MODE" in
    stock)
        tear_down
        bring_up_stock
        ;;
    wgzk)
        tear_down
        bring_up_wgzk
        ;;
    *)
        echo "bad mode: $MODE" >&2; exit 1 ;;
esac
