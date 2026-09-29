#!/bin/bash
# Provision the GATEWAY VM for protocol R1 (docs/protocol-r1.md).
#
# The interface starts without peers. The daemon registers the session key of
# a client only after it has verified the proof that came with the initiation.
# Keys are generated on the host by vagrant/keygen.sh.
#
# Environment:
#   WGZK_VARIANT  zk-pq (default) or zk-only
#   WGZK_EPOCH    credential epoch, default 1; must match the client
set -euo pipefail

KEYS="/vagrant/vagrant/keys"
IFACE="wg1r"
LISTEN_PORT=51921
GW_ADDR="fd57:475a:4b00::1"
VARIANT="${WGZK_VARIANT:-zk-pq}"
EPOCH="${WGZK_EPOCH:-1}"

for f in private_right zk.env mlkem.env; do
    [ -f "$KEYS/$f" ] || { echo "ERROR: $KEYS/$f not found. Run: bash vagrant/keygen.sh"; exit 1; }
done
case "$VARIANT" in
    zk-pq|zk-only) ;;
    *) echo "ERROR: WGZK_VARIANT=$VARIANT, expected zk-pq or zk-only"; exit 1 ;;
esac

# The gateway gets the public half of the credential only.
WGZK_PK_HEX=$(grep '^WGZK_PK_HEX=' "$KEYS/zk.env" | cut -d= -f2)
MLKEM_DK_SEED=$(grep '^MLKEM_DK_SEED=' "$KEYS/mlkem.env" | cut -d= -f2)
MLKEM_CERT_PEM=$(grep '^MLKEM_CERT_PEM=' "$KEYS/mlkem.env" | cut -d= -f2-)
MLKEM_KEY_PEM=$(grep '^MLKEM_KEY_PEM=' "$KEYS/mlkem.env" | cut -d= -f2-)

systemctl stop wgzk 2>/dev/null || true
ART="/vagrant/vagrant/artifacts"
[ -f "$ART/wg-zk-daemon" ] || { echo "ERROR: $ART/wg-zk-daemon not found. Run: bash vagrant/build-artifacts.sh"; exit 1; }
install -m 755 "$ART/wg-zk-daemon" /usr/local/bin/wg-zk-daemon
if [ -f "$ART/wg-zk-daemon-fault" ]; then
    install -m 755 "$ART/wg-zk-daemon-fault" /usr/local/bin/wg-zk-daemon-fault
fi

# ── WireGuard interface, no peers ─────────────────────────────────────────────
ip link del "$IFACE" 2>/dev/null || true
ip link add "$IFACE" type wireguard
wg set "$IFACE" private-key "$KEYS/private_right" listen-port "$LISTEN_PORT"
ip link set "$IFACE" mtu 1380
ip -6 addr add "${GW_ADDR}/64" dev "$IFACE"
ip link set "$IFACE" up

# ── Daemon ────────────────────────────────────────────────────────────────────
# PEM files with real newlines (printf %b unescapes \n)
umask 077
printf "%b\n" "$MLKEM_CERT_PEM" > /etc/wgzk-cert.pem
printf "%b\n" "$MLKEM_KEY_PEM"  > /etc/wgzk-key.pem

cat > /etc/wgzk.env <<EOF
WGZK_MODE=gateway
WGZK_EPOCH=${EPOCH}
WGZK_PK_HEX=${WGZK_PK_HEX}
MLKEM_DK_SEED=${MLKEM_DK_SEED}
WG_IFACE=${IFACE}
EOF
if [ "$VARIANT" = "zk-only" ]; then
    echo "WGZK_DISABLE_MLKEM=1" >> /etc/wgzk.env
fi
chmod 600 /etc/wgzk.env
umask 022

# Wrapper: loads the PEM files (a systemd EnvironmentFile cannot hold multi-line values)
cat > /usr/local/bin/wgzk-start.sh <<'WRAPPER'
#!/bin/bash
export MLKEM_CERT_PEM=$(cat /etc/wgzk-cert.pem)
export MLKEM_KEY_PEM=$(cat /etc/wgzk-key.pem)
exec /usr/local/bin/wg-zk-daemon
WRAPPER
chmod +x /usr/local/bin/wgzk-start.sh

cat > /etc/systemd/system/wgzk.service <<'EOF'
[Unit]
Description=wgzk daemon (gateway)
After=network.target
[Service]
EnvironmentFile=/etc/wgzk.env
ExecStart=/usr/local/bin/wgzk-start.sh
Restart=on-failure
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable wgzk
systemctl restart wgzk
sleep 2
systemctl is-active wgzk && echo "==> wgzk daemon running (gateway, $VARIANT, epoch $EPOCH)" \
    || { journalctl -u wgzk --no-pager -n 20; exit 1; }
wg show "$IFACE"
