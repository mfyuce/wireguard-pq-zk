#!/bin/bash
# Build and configure PQ-WireGuard in one machine.
#   provision.sh gateway|client <address of the gateway on the test network>
#
# Keys: each machine creates its McEliece key pair once and puts the public
# half into the shared folder. The gateway is provisioned first and cannot know
# the key of the client then; "provision.sh gateway ..." is therefore run once
# more after the client exists (the measurement does that).
set -euo pipefail

ROLE="${1:?gateway or client}"
GW_IP="${2:?address of the gateway}"
SRC="/vagrant/vagrant/artifacts/pqwireguard-20200402"
PUB="/vagrant/vagrant/keys/pqwireguard"
BUILD="/opt/pqwireguard"
CONF="/wg_config"
IFACE="wg0"
PORT=51921
GW_ADDR="fd57:475a:4b00::1"
CL_ADDR="fd57:475a:4b00::2"
TUNNEL_NET="fd57:475a:4b00::/64"

[ -d "$SRC/WireGuard/src" ] || { echo "ERROR: $SRC not found. Run: bash vagrant/fetch-pqwireguard.sh"; exit 1; }
grep -q avx2 /proc/cpuinfo || { echo "ERROR: the guest does not see AVX2"; exit 1; }
[ "$(uname -r)" = "4.15.0-91-generic" ] || { echo "ERROR: kernel $(uname -r), expected 4.15.0-91-generic"; exit 1; }

if [ ! -x /usr/bin/wg ] || [ ! -f "$BUILD/WireGuard/src/wireguard.ko" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential "linux-headers-$(uname -r)" libmnl-dev libelf-dev pkg-config >/dev/null
    rm -rf "$BUILD"
    mkdir -p "$BUILD"
    cp -r "$SRC/WireGuard" "$BUILD/"
    make -C "$BUILD/WireGuard/src" -j"$(nproc)" > "$BUILD/build.log" 2>&1 ||
        { echo "ERROR: the build failed"; tail -40 "$BUILD/build.log"; exit 1; }
    make -C "$BUILD/WireGuard/src" install >> "$BUILD/build.log" 2>&1 ||
        { echo "ERROR: the installation failed"; tail -40 "$BUILD/build.log"; exit 1; }
fi
echo "==> kernel $(uname -r), module $(modinfo -F version wireguard 2>/dev/null || echo '?')"

mkdir -p "$CONF" "$PUB"
chmod 700 "$CONF"
if [ ! -f "$CONF/prikey" ]; then
    (umask 077; wg mckey "$CONF/prikey" "$CONF/pubkey")
fi
cp "$CONF/pubkey" "$PUB/$ROLE.pubkey"

ip link del "$IFACE" 2>/dev/null || true
rmmod wireguard 2>/dev/null || true
modprobe wireguard

case "$ROLE" in
    gateway)
        cat > "$CONF/$IFACE.conf" <<CONFIG
[Interface]
McEliecePrivateKey = $CONF/prikey
McEliecePublicKey = $CONF/pubkey
ListenPort = $PORT
CONFIG
        if [ -f "$PUB/client.pubkey" ]; then
            cat >> "$CONF/$IFACE.conf" <<CONFIG

[Peer]
McEliecePublicKey = $PUB/client.pubkey
AllowedIPs = $CL_ADDR/128
CONFIG
        fi
        ADDR="$GW_ADDR/64"
        ;;
    client)
        [ -f "$PUB/gateway.pubkey" ] || { echo "ERROR: key of the gateway missing"; exit 1; }
        cat > "$CONF/$IFACE.conf" <<CONFIG
[Interface]
McEliecePrivateKey = $CONF/prikey
McEliecePublicKey = $CONF/pubkey

[Peer]
McEliecePublicKey = $PUB/gateway.pubkey
Endpoint = $GW_IP:$PORT
AllowedIPs = $TUNNEL_NET
CONFIG
        ADDR="$CL_ADDR/128"
        ;;
    *)
        echo "ERROR: role $ROLE"; exit 1 ;;
esac

# The same steps bring the interface up again before every trial.
cat > /usr/local/bin/pqwg-up <<UP
#!/bin/bash
set -e
ip link del $IFACE 2>/dev/null || true
ip link add dev $IFACE type wireguard
ip link set $IFACE mtu 1380
ip -6 addr add $ADDR dev $IFACE
wg setconf $IFACE $CONF/$IFACE.conf
ip link set $IFACE up
ip -6 route replace $TUNNEL_NET dev $IFACE
UP
chmod 755 /usr/local/bin/pqwg-up
pqwg-up
wg show "$IFACE" | sed -E 's/(private key|preshared key): .*/\1: (hidden)/' | cut -c1-120
