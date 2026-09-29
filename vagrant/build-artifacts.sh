#!/bin/bash
# Build the kernel module and the daemon on the host and collect them in
# vagrant/artifacts/, from where the machines install them. The directory is
# not tracked. Run in any directory:
#
#   bash vagrant/build-artifacts.sh
#
# Also builds the two key generators that vagrant/keygen.sh runs.
# The daemon is built twice: as it is released, and with the feature
# "fault-injection" for the negative acceptance tests (wg-zk-daemon-fault).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/vagrant/artifacts"
KERNEL="6.8.0-59-generic"
DAEMON="$ROOT/userspace/wg-zk-daemon"

mkdir -p "$OUT"

echo "==> kernel module for $KERNEL"
make -C "/lib/modules/$KERNEL/build" M="$ROOT/wireguard-6.8" CONFIG_WIREGUARD=m modules
install -m 644 "$ROOT/wireguard-6.8/wireguard.ko" "$OUT/wireguard.ko"

# The target directory may be set outside the repository (cargo configuration).
target_dir() {
    cargo metadata --format-version 1 --no-deps |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

echo "==> key generators"
for tool in gen-pk gen-mlkem; do
    cd "$ROOT/userspace/$tool"
    cargo build --release
    install -m 755 "$(target_dir)/release/$tool" "$OUT/$tool"
done

echo "==> daemon"
cd "$DAEMON"
TARGET="$(target_dir)"
cargo build --release --locked
install -m 755 "$TARGET/release/wg-zk-daemon" "$OUT/wg-zk-daemon"

if grep -q '^fault-injection' Cargo.toml; then
    echo "==> daemon with fault injection"
    cargo build --release --locked --features fault-injection --target-dir "$TARGET/wgzk-fault"
    install -m 755 "$TARGET/wgzk-fault/release/wg-zk-daemon" "$OUT/wg-zk-daemon-fault"
fi

cd "$ROOT"
{
    echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit $(git rev-parse HEAD) dirty_files=$(git status --porcelain | wc -l)"
    echo "kernel $KERNEL"
    echo "rustc $(rustc --version)"
    (cd "$OUT" && sha256sum wireguard.ko wg-zk-daemon* gen-pk gen-mlkem)
} > "$OUT/MANIFEST"
cat "$OUT/MANIFEST"
