#!/bin/bash
# Provision the CLIENT VM for protocol R1 (docs/protocol-r1.md).
#
# The client has no long-term WireGuard key. "wg-zk-daemon new-connection"
# gives the interface a fresh key and the tunnel address derived from it; run
# it again to start another connection.
# Keys are generated on the host by vagrant/keygen.sh.
#
# Environment:
#   PEER_IP       address of the gateway on the test network
#   WGZK_VARIANT  zk-pq (default) or zk-only
#   WGZK_EPOCH    credential epoch, default 1; must match the gateway
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.1}"
KEYS="/vagrant/vagrant/keys"
IFACE="wg1l"
GW_PORT=51921
TUNNEL_NET="fd57:475a:4b00::/64"
VARIANT="${WGZK_VARIANT:-zk-pq}"
EPOCH="${WGZK_EPOCH:-1}"

for f in public_right zk.env mlkem.env; do
    [ -f "$KEYS/$f" ] || { echo "ERROR: $KEYS/$f not found. Run: bash vagrant/keygen.sh"; exit 1; }
done
case "$VARIANT" in
    zk-pq|zk-only) ;;
    *) echo "ERROR: WGZK_VARIANT=$VARIANT, expected zk-pq or zk-only"; exit 1 ;;
esac

WGZK_SK_HEX=$(grep '^WGZK_SK_HEX=' "$KEYS/zk.env" | cut -d= -f2)
MLKEM_EK=$(grep '^MLKEM_EK=' "$KEYS/mlkem.env" | cut -d= -f2)
MLKEM_CERT_FP=$(grep '^MLKEM_CERT_FP=' "$KEYS/mlkem.env" | cut -d= -f2)

systemctl stop wgzk 2>/dev/null || true
ART="/vagrant/vagrant/artifacts"
[ -f "$ART/wg-zk-daemon" ] || { echo "ERROR: $ART/wg-zk-daemon not found. Run: bash vagrant/build-artifacts.sh"; exit 1; }
install -m 755 "$ART/wg-zk-daemon" /usr/local/bin/wg-zk-daemon
if [ -f "$ART/wg-zk-daemon-fault" ]; then
    install -m 755 "$ART/wg-zk-daemon-fault" /usr/local/bin/wg-zk-daemon-fault
fi

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link del "$IFACE" 2>/dev/null || true
ip link add "$IFACE" type wireguard
ip link set "$IFACE" mtu 1380
# Session key and tunnel address of the first connection
wg-zk-daemon new-connection --iface "$IFACE"
wg set "$IFACE" \
    peer "$(cat $KEYS/public_right)" \
    allowed-ips "$TUNNEL_NET" \
    endpoint "${PEER_IP}:${GW_PORT}"
ip link set "$IFACE" up
ip -6 route replace "$TUNNEL_NET" dev "$IFACE"

# ── Daemon ────────────────────────────────────────────────────────────────────
umask 077
cat > /etc/wgzk.env <<EOF
WGZK_MODE=client
WGZK_EPOCH=${EPOCH}
WGZK_SK_HEX=${WGZK_SK_HEX}
MLKEM_SERVER_EK=${MLKEM_EK}
MLKEM_SERVER_ADDR=${PEER_IP}:51821
MLKEM_CERT_FP=${MLKEM_CERT_FP}
WG_IFACE=${IFACE}
EOF
if [ "$VARIANT" = "zk-only" ]; then
    echo "WGZK_DISABLE_MLKEM=1" >> /etc/wgzk.env
fi
chmod 600 /etc/wgzk.env
umask 022

cat > /etc/systemd/system/wgzk.service <<'EOF'
[Unit]
Description=wgzk daemon (client)
After=network.target
[Service]
EnvironmentFile=/etc/wgzk.env
ExecStart=/usr/local/bin/wg-zk-daemon
Restart=on-failure
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable wgzk
systemctl restart wgzk
sleep 2
systemctl is-active wgzk && echo "==> wgzk daemon running (client, $VARIANT, epoch $EPOCH)" \
    || { journalctl -u wgzk --no-pager -n 20; exit 1; }
wg show "$IFACE"
