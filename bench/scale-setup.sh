#!/bin/bash
# Add N additional WireGuard peers on each side of the existing wgzk tunnel so
# that `scale-run.sh` can trigger N handshakes in parallel against the single
# gateway daemon. The Schnorr ZK pubkey is group-shared (unlinkability), so all
# peers authenticate as the same credential; only the per-peer WG keypair and
# allowed-ips differ.
#
# Usage (host): bash bench/scale-setup.sh N            — orchestrates both VMs
#        (in-VM) sudo SCALE_SIDE={client,gateway} scale-setup.sh N
#
# Host-side mode:  invokes `vagrant ssh <side> -c "...scale-setup.sh..."` twice.
# In-VM mode:      generates N WG keypairs, writes /etc/wgzk-scale.env, sets N
#                  peers via `wg set`, adds routes/addrs, writes the per-peer
#                  metadata that scale-run.sh consumes.
#
# Layout (N peers, index i in [0..N-1]):
#   client 10.10.10.{100+i}/32      on dum0l
#   gateway 10.20.10.{100+i}/32     on dum0r
#   client  wg1l peer pub_right[i]  allowed-ips 10.20.10.{100+i}/32
#   gateway wg1r peer pub_left[i]   allowed-ips 10.10.10.{100+i}/32
#
# Keys are symmetric: pub_left[i] ↔ pub_right[i] form the i-th tunnel pair.
set -euo pipefail

N="${1:-64}"
SIDE="${SCALE_SIDE:-}"

if [ -z "$SIDE" ]; then
    # Host mode: delegate to both VMs.
    cd "$(dirname "$0")/.."
    # Step 1: generate N keypairs on host (shared source of truth).
    KEYS_DIR="vagrant/keys/scale"
    mkdir -p "$KEYS_DIR"
    for i in $(seq 0 $((N-1))); do
        if [ ! -s "$KEYS_DIR/priv_l_$i" ]; then
            wg genkey | tee "$KEYS_DIR/priv_l_$i" | wg pubkey > "$KEYS_DIR/pub_l_$i"
            wg genkey | tee "$KEYS_DIR/priv_r_$i" | wg pubkey > "$KEYS_DIR/pub_r_$i"
        fi
    done
    chmod 600 "$KEYS_DIR"/priv_*
    echo "==> $N keypairs ready in $KEYS_DIR"

    # Step 2: provision gateway, then client.
    vagrant ssh gateway -c "sudo SCALE_SIDE=gateway bash /vagrant/bench/scale-setup.sh $N"
    vagrant ssh client  -c "sudo SCALE_SIDE=client  bash /vagrant/bench/scale-setup.sh $N"
    exit 0
fi

KEYS=/vagrant/vagrant/keys/scale

case "$SIDE" in
    client)
        IFACE=wg1l
        DUM=dum0l
        MY_SUBNET_BASE=10.10.10        # our dummy IPs
        PEER_SUBNET_BASE=10.20.10      # gateway dummy IPs (we dial these)
        MY_PRIV_PREFIX=priv_l
        PEER_PUB_PREFIX=pub_r
        ENDPOINT="192.168.100.1:51921"
        ;;
    gateway)
        IFACE=wg1r
        DUM=dum0r
        MY_SUBNET_BASE=10.20.10
        PEER_SUBNET_BASE=10.10.10
        MY_PRIV_PREFIX=priv_r
        PEER_PUB_PREFIX=pub_l
        ENDPOINT=""                    # responder — no endpoint needed
        ;;
    *) echo "bad SCALE_SIDE=$SIDE" >&2; exit 1 ;;
esac

for i in $(seq 0 $((N-1))); do
    OFFSET=$((100 + i))
    MY_IP="$MY_SUBNET_BASE.$OFFSET"
    PEER_IP="$PEER_SUBNET_BASE.$OFFSET"
    PEER_PUB="$(cat $KEYS/${PEER_PUB_PREFIX}_$i)"

    # Assign our dummy IP so outbound sources bind correctly.
    ip addr add "$MY_IP/32" dev "$DUM" 2>/dev/null || true

    # Register peer. Use allowed-ips = single /32 on each side so routing is
    # deterministic per peer.
    if [ "$SIDE" = "client" ]; then
        wg set "$IFACE" peer "$PEER_PUB" \
            endpoint "$ENDPOINT" \
            allowed-ips "$PEER_IP/32"
        # Route to this peer's dummy IP via the wg interface.
        ip route replace "$PEER_IP/32" dev "$IFACE"
    else
        wg set "$IFACE" peer "$PEER_PUB" \
            allowed-ips "$PEER_IP/32"
    fi
done
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w "net.ipv4.conf.$IFACE.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.$DUM.rp_filter=0"   >/dev/null || true

echo "==> $SIDE: $N peers registered on $IFACE"
