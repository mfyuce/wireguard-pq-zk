#!/bin/bash
# Configure one machine for the baseline: WireGuard as shipped with the kernel,
# same addresses and port as the wgzk configuration, long-term keys on both sides.
#
#   10-stock.sh gateway|client [psk]
#
# With "psk" both sides use the preshared key in vagrant/keys/stock.psk, which
# is created if it does not exist.
set -euo pipefail

ROLE="${1:?gateway or client}"
WITH_PSK="${2:-}"
KEYS="/vagrant/vagrant/keys"
IFACE="wg0"
GW_IP="192.168.100.1"
GW_PORT=51921
GW_ADDR="fd57:475a:4b00::1"
CL_ADDR="fd57:475a:4b00::2"
TUNNEL_NET="fd57:475a:4b00::/64"
STOCK="/lib/modules/$(uname -r)/kernel/drivers/net/wireguard/wireguard.ko"

[ -f "$STOCK" ] || { echo "ERROR: $STOCK not found"; exit 1; }

systemctl stop wgzk 2>/dev/null || true
for dev in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'); do
    ip link del "$dev"
done
rmmod wireguard 2>/dev/null || true
for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
           curve25519-x86_64 libcurve25519-generic chacha20poly1305; do
    modprobe "$mod" 2>/dev/null || true
done
insmod "$STOCK"
LOADED="$(cat /sys/module/wireguard/srcversion)"
[ "$LOADED" = "$(modinfo -F srcversion "$STOCK")" ] || { echo "ERROR: loaded module is not the stock one"; exit 1; }
echo "==> stock wireguard loaded, srcversion $LOADED"

PSK=()
if [ "$WITH_PSK" = "psk" ]; then
    [ -f "$KEYS/stock.psk" ] || (umask 077; wg genpsk > "$KEYS/stock.psk")
    PSK=(preshared-key "$KEYS/stock.psk")
fi

ip link add "$IFACE" type wireguard
ip link set "$IFACE" mtu 1380
case "$ROLE" in
    gateway)
        wg set "$IFACE" private-key "$KEYS/private_right" listen-port "$GW_PORT"
        ip -6 addr add "${GW_ADDR}/64" dev "$IFACE"
        ip link set "$IFACE" up
        wg set "$IFACE" peer "$(cat "$KEYS/public_left")" allowed-ips "${CL_ADDR}/128" "${PSK[@]}"
        ;;
    client)
        wg set "$IFACE" private-key "$KEYS/private_left"
        ip -6 addr add "${CL_ADDR}/128" dev "$IFACE"
        ip link set "$IFACE" up
        wg set "$IFACE" peer "$(cat "$KEYS/public_right")" allowed-ips "$TUNNEL_NET" \
            endpoint "${GW_IP}:${GW_PORT}" "${PSK[@]}"
        ip -6 route replace "$TUNNEL_NET" dev "$IFACE"
        ;;
    *)
        echo "ERROR: role $ROLE, expected gateway or client"; exit 1 ;;
esac
wg show "$IFACE"
