#!/bin/bash
# Switch the wgzk daemon between ZK-only and ZK+PQ variants on one VM.
# Usage (inside VM):  variant-switch.sh {zk-only|zk-pq}
# Reads/writes /etc/wgzk.env and restarts the wgzk systemd unit.
set -euo pipefail

if [ $# -lt 1 ]; then echo "usage: $0 zk-only|zk-pq" >&2; exit 1; fi
VARIANT="$1"
ENV=/etc/wgzk.env

case "$VARIANT" in
  zk-only)
    # Remove any existing WGZK_DISABLE_MLKEM line, then add =1
    sed -i '/^WGZK_DISABLE_MLKEM=/d' "$ENV"
    echo "WGZK_DISABLE_MLKEM=1" >> "$ENV"
    ;;
  zk-pq)
    sed -i '/^WGZK_DISABLE_MLKEM=/d' "$ENV"
    ;;
  *)
    echo "unknown variant: $VARIANT" >&2
    exit 1
    ;;
esac

systemctl restart wgzk
sleep 1
systemctl is-active wgzk >/dev/null && echo "wgzk active in variant=$VARIANT" || {
  journalctl -u wgzk --no-pager -n 10 >&2
  exit 1
}
