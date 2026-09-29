#!/bin/bash
# The kernel of Ubuntu 18.04 at the date of the PQ-WireGuard artefact (April
# 2020). Later kernels of the 4.15 series carry backports that the
# compatibility layer of the artefact defines a second time, and the build
# fails. Vagrant reboots after this script.
set -euo pipefail

KERNEL="4.15.0-91-generic"

echo "==> Current kernel: $(uname -r)"
if [ "$(uname -r)" = "$KERNEL" ]; then
    echo "==> Already on $KERNEL"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq "linux-image-$KERNEL" "linux-modules-$KERNEL" \
    "linux-modules-extra-$KERNEL" "linux-headers-$KERNEL" >/dev/null
update-grub 2>/dev/null

POS=$(awk '
  /submenu.*Advanced options/ { in_sub = 1; pos = 0; next }
  in_sub && /menuentry.*'"$KERNEL"'/ && !/recovery/ { print pos; exit }
  in_sub && /menuentry / { pos++ }
' /boot/grub/grub.cfg)
[ -n "$POS" ] || { echo "ERROR: $KERNEL not in the boot menu"; exit 1; }
# Files of grub.d are read after /etc/default/grub; the cloud image sets its default there.
echo "GRUB_DEFAULT=\"1>$POS\"" > /etc/default/grub.d/99-pqwireguard.cfg
update-grub 2>/dev/null
echo "==> $KERNEL installed, boot entry 1>$POS"
