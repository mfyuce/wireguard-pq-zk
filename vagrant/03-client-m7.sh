#!/bin/bash
# Provision the CLIENT VM with N concurrent interfaces for M-7 (concurrency).
#
# One wg-zk-daemon instance per interface, wgc0..wgc(N-1), all filtering on their own
# WG_IFACE (userspace/wg-zk-daemon/src/client.rs:13-14: events of another interface are
# ignored, so one daemon per interface runs side by side with no daemon change). Each
# instance's WG_IFACE is set with `env` on ExecStart, not `Environment=`, because
# EnvironmentFile=/etc/wgzk.env (shared, for the credential and ML-KEM settings every
# instance needs) would otherwise win over a plain Environment= and every instance would
# filter for the same interface.
#
# Each interface gets its own routing table and an oif-based rule, not a from-address rule:
# `new-connection` gives an interface a fresh address every round (see
# bench/guest/concurrent_trials.py), so a from-address rule would need rewriting every round;
# an oif rule, set up once here, does not.
#
# Environment:
#   PEER_IP        address of the gateway on the test network
#   WGZK_VARIANT   zk-pq (default) or zk-only
#   WGZK_EPOCH     credential epoch, default 1; must match the gateway
#   WGZK_M7_N      number of concurrent interfaces, default 2
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.1}"
KEYS="/vagrant/vagrant/keys"
GW_PORT=51921
TUNNEL_NET="fd57:475a:4b00::/64"
VARIANT="${WGZK_VARIANT:-zk-pq}"
EPOCH="${WGZK_EPOCH:-1}"
N="${WGZK_M7_N:-2}"

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

ART="/vagrant/vagrant/artifacts"
[ -f "$ART/wg-zk-daemon" ] || { echo "ERROR: $ART/wg-zk-daemon not found. Run: bash vagrant/build-artifacts.sh"; exit 1; }
install -m 755 "$ART/wg-zk-daemon" /usr/local/bin/wg-zk-daemon

# ── stop any previous M-7 run and the single-interface wgzk service, if present ────
systemctl stop wgzk 2>/dev/null || true
for u in /etc/systemd/system/wgzk-m7@*.service; do
    [ -e "$u" ] || continue
    inst="$(basename "$u" .service)"
    systemctl stop "$inst" 2>/dev/null || true
done
for k in $(seq 0 31); do
    ip link del "wgc$k" 2>/dev/null || true
    ip -6 rule del table $((100 + k)) 2>/dev/null || true
done

# ── shared env: same credential and ML-KEM settings for every instance ─────────────
umask 077
cat > /etc/wgzk.env <<EOF
WGZK_MODE=client
WGZK_EPOCH=${EPOCH}
WGZK_SK_HEX=${WGZK_SK_HEX}
MLKEM_SERVER_EK=${MLKEM_EK}
MLKEM_SERVER_ADDR=${PEER_IP}:51821
MLKEM_CERT_FP=${MLKEM_CERT_FP}
WG_IFACE=wgc0
EOF
if [ "$VARIANT" = "zk-only" ]; then
    echo "WGZK_DISABLE_MLKEM=1" >> /etc/wgzk.env
fi
chmod 600 /etc/wgzk.env
umask 022

# ── template unit: %i is the interface name (wgc0, wgc1, ...) ─────────────────────
# Each instance (wgzk-m7@wgc0.service, wgzk-m7@wgc1.service, ...) is already its own
# journald stream, queryable as -u wgzk-m7@wgcK.service: no separate log file is needed to
# keep instances apart, and journald's own __REALTIME_TIMESTAMP (which bench/concurrency.py
# reads the same way bench/latency.py reads it from -u wgzk) is what bench/latency.py's
# client/gateway [timing] correlation depends on. The daemon's own eprintln! carries no
# timestamp of its own (userspace/wg-zk-daemon/src/main.rs), so redirecting stdout/stderr
# straight to a file instead of journald, as first suggested, would have thrown that
# timestamp away.
cat > /etc/systemd/system/wgzk-m7@.service <<'EOF'
[Unit]
Description=wgzk daemon (M-7 concurrency, interface %i)
After=network.target
[Service]
EnvironmentFile=/etc/wgzk.env
ExecStart=/usr/bin/env WG_IFACE=%i /usr/local/bin/wg-zk-daemon
WorkingDirectory=/run
Restart=on-failure
RestartSec=1
EOF
systemctl daemon-reload

for k in $(seq 0 $((N - 1))); do
    iface="wgc$k"
    table=$((100 + k))
    ip link add "$iface" type wireguard
    ip link set "$iface" mtu 1380
    wg-zk-daemon new-connection --iface "$iface"
    wg set "$iface" \
        peer "$(cat $KEYS/public_right)" \
        allowed-ips "$TUNNEL_NET" \
        endpoint "${PEER_IP}:${GW_PORT}"
    ip link set "$iface" up
    ip -6 route replace "$TUNNEL_NET" dev "$iface" table "$table"
    ip -6 rule add oif "$iface" lookup "$table" pref $((1000 + k))
    systemctl enable --now "wgzk-m7@${iface}.service"
done

sleep 2
fail=0
for k in $(seq 0 $((N - 1))); do
    iface="wgc$k"
    systemctl is-active "wgzk-m7@${iface}.service" >/dev/null || { echo "==> $iface daemon not active"; fail=1; }
done
[ "$fail" = 0 ] || { for k in $(seq 0 $((N - 1))); do echo "--- wgc$k ---"; journalctl -u "wgzk-m7@wgc$k.service" --no-pager -n 20; done; exit 1; }
echo "==> $N wgzk-m7 daemons running ($VARIANT, epoch $EPOCH)"
for k in $(seq 0 $((N - 1))); do wg show "wgc$k"; done
