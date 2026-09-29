#!/bin/bash
# Copy wireguard.ko from host (via /vagrant) and load it.
# Runs on every "vagrant up" so code changes on host take effect immediately.
set -euo pipefail

KERNEL="6.8.0-59-generic"
KO_SRC="/vagrant/vagrant/artifacts/wireguard.ko"
KO_DST="/lib/modules/${KERNEL}/extra/wireguard.ko"

echo "==> Kernel: $(uname -r)"
if [ "$(uname -r)" != "$KERNEL" ]; then
    echo "ERROR: expected kernel $KERNEL but running $(uname -r)"
    echo "       Re-build the base box: cd vagrant && bash build-base.sh"
    exit 1
fi

if [ ! -f "$KO_SRC" ]; then
    echo "ERROR: $KO_SRC not found."
    echo "       Build on host: bash vagrant/build-artifacts.sh"
    exit 1
fi

# Remove previously loaded wireguard (stock or old custom)
systemctl stop wgzk 2>/dev/null || true
for dev in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'); do
    ip link del "$dev"
done
rmmod wireguard 2>/dev/null || true

# Load dependencies (order matters — same as README)
for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
           curve25519-x86_64 libcurve25519-generic chacha20poly1305 \
           gcm aes_generic aesni_intel af_alg; do
    modprobe "$mod" 2>/dev/null || true
done

# Install and load the fresh .ko from host
install -D -m 644 "$KO_SRC" "$KO_DST"
insmod "$KO_DST" && echo "==> insmod OK" || { echo "ERROR: insmod failed"; dmesg | tail -10; exit 1; }

sleep 1

echo "==> lsmod:"
lsmod | grep wireguard || echo "(wireguard not in lsmod)"

# The list is read completely before it is searched: "genl | grep -q" fails
# under pipefail whenever grep finds the name before genl has finished writing.
FAMILIES="$(genl ctrl list 2>/dev/null || true)"
if grep -q 'Name: wgzk' <<<"$FAMILIES"; then
    echo "==> wireguard.ko loaded OK — wgzk genl registered"
else
    echo "ERROR: wgzk genl family not found"
    dmesg | tail -20
    exit 1
fi
