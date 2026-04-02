#!/bin/bash
# Provision the CLIENT (LEFT) VM.
# All keys pre-generated on host by vagrant/keygen.sh
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.1}"
KEYS="/vagrant/vagrant/keys"

[ -f "$KEYS/private_left" ] || { echo "ERROR: keys not found. Run: bash vagrant/keygen.sh"; exit 1; }
[ -f "$KEYS/zk.env" ]       || { echo "ERROR: zk.env not found"; exit 1; }
[ -f "$KEYS/mlkem.env" ]    || { echo "ERROR: mlkem.env not found. Run: bash vagrant/keygen.sh"; exit 1; }
source "$KEYS/zk.env"
MLKEM_EK=$(grep     "^MLKEM_EK="      "$KEYS/mlkem.env" | cut -d= -f2)
MLKEM_CERT_FP=$(grep "^MLKEM_CERT_FP=" "$KEYS/mlkem.env" | cut -d= -f2)

install -m 755 /vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon /usr/local/bin/wg-zk-daemon

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link add wg1l type wireguard 2>/dev/null || true
ip addr add 192.168.1.1/32 dev wg1l 2>/dev/null || true
ip link set wg1l up
wg set wg1l private-key "$KEYS/private_left" listen-port 51821
ip link set wg1l mtu 1380
wg set wg1l \
    peer "$(cat $KEYS/public_right)" \
    allowed-ips 10.20.10.0/24 \
    endpoint "${PEER_IP}:51921" \
    persistent-keepalive 5
ip route replace 10.20.10.0/24 dev wg1l

# ── Dummy interface ───────────────────────────────────────────────────────────
ip link add dum0l type dummy 2>/dev/null || true
ip addr add 10.10.10.10/24 dev dum0l 2>/dev/null || true
ip link set dum0l up

# ── rp_filter ─────────────────────────────────────────────────────────────────
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.wg1l.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.dum0l.rp_filter=0 >/dev/null || true

# ── Daemon ────────────────────────────────────────────────────────────────────
WG_PEER_PUBKEY="$(cat $KEYS/public_right)"
cat > /etc/wgzk.env <<EOF
WGZK_MODE=client
WGZK_SK_HEX=${WGZK_SK_HEX}
WGZK_PK_HEX=${WGZK_PK_HEX}
MLKEM_SERVER_EK=${MLKEM_EK}
MLKEM_SERVER_ADDR=${PEER_IP}:51821
MLKEM_CERT_FP=${MLKEM_CERT_FP}
WG_IFACE=wg1l
WG_PEER_PUBKEY=${WG_PEER_PUBKEY}
EOF
cat > /etc/systemd/system/wgzk.service <<'EOF'
[Unit]
Description=WireGuard ZK Daemon
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
systemctl is-active wgzk && echo "==> wgzk daemon running (client)" || { journalctl -u wgzk --no-pager -n 20; exit 1; }
wg show wg1l
