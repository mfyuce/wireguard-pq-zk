#!/bin/bash
# Configure one machine for Rosenpass (official release binary) on top of
# WireGuard as shipped with the kernel. Same addresses as the other systems.
#
#   11-rosenpass.sh gateway|client keys    create the keys of this machine (once)
#   11-rosenpass.sh gateway start          run the exchange as a service
#   11-rosenpass.sh client prepare         everything but the exchange itself
#
# The exchange of the client is started by the measurement
# (bench/guest/rosenpass_trials.py), because its duration is what is measured.
set -euo pipefail

ROLE="${1:?gateway or client}"
ACTION="${2:?keys, start or prepare}"
VERSION="0.2.3"
ART="/vagrant/vagrant/artifacts/rosenpass-${VERSION}"
PUB="/vagrant/vagrant/keys/rosenpass"
SECRET="/etc/rosenpass/${ROLE}.secret"
DEV="rosenpass0"
GW_IP="192.168.100.1"
RP_PORT=9999
GW_ADDR="fd57:475a:4b00::1"
CL_ADDR="fd57:475a:4b00::2"
TUNNEL_NET="fd57:475a:4b00::/64"
STOCK="/lib/modules/$(uname -r)/kernel/drivers/net/wireguard/wireguard.ko"

[ -x "$ART/bin/rosenpass" ] || { echo "ERROR: $ART not found. Run: bash vagrant/fetch-rosenpass.sh"; exit 1; }
install -m 755 "$ART/bin/rosenpass" /usr/local/bin/rosenpass
install -m 755 "$ART/bin/rp" /usr/local/bin/rp

stock_module() {
    systemctl stop wgzk rosenpass 2>/dev/null || true
    pkill -x rosenpass 2>/dev/null || true
    for dev in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'); do
        ip link del "$dev"
    done
    rmmod wireguard 2>/dev/null || true
    for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
               curve25519-x86_64 libcurve25519-generic chacha20poly1305; do
        modprobe "$mod" 2>/dev/null || true
    done
    insmod "$STOCK"
    [ "$(cat /sys/module/wireguard/srcversion)" = "$(modinfo -F srcversion "$STOCK")" ] ||
        { echo "ERROR: loaded module is not the stock one"; exit 1; }
}

case "$ROLE/$ACTION" in
    gateway/keys|client/keys)
        mkdir -p /etc/rosenpass "$PUB"
        [ -d "$SECRET" ] || rp genkey "$SECRET"
        rm -rf "${PUB:?}/${ROLE}.public"
        rp pubkey "$SECRET" "$PUB/${ROLE}.public"
        ls -l "$PUB/${ROLE}.public"
        ;;
    gateway/start)
        [ -d "$PUB/client.public" ] || { echo "ERROR: keys of the client missing"; exit 1; }
        stock_module
        cat > /etc/systemd/system/rosenpass.service <<UNIT
[Unit]
Description=Rosenpass key exchange (gateway)
After=network.target
[Service]
ExecStart=/usr/local/bin/rp exchange $SECRET dev $DEV listen ${GW_IP}:${RP_PORT} peer $PUB/client.public allowed-ips ${CL_ADDR}/128
Restart=on-failure
RestartSec=1
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl restart rosenpass
        for _ in $(seq 50); do
            ip link show "$DEV" >/dev/null 2>&1 && break
            sleep 0.1
        done
        ip link set "$DEV" mtu 1380
        ip -6 addr add "${GW_ADDR}/64" dev "$DEV"
        sleep 1
        systemctl is-active rosenpass
        wg show "$DEV"
        ;;
    client/prepare)
        [ -d "$PUB/gateway.public" ] || { echo "ERROR: keys of the gateway missing"; exit 1; }
        stock_module
        echo "==> stock wireguard loaded; the exchange is started by the measurement"
        ;;
    *)
        echo "ERROR: $ROLE $ACTION: expected gateway|client and keys|start|prepare"; exit 1 ;;
esac
