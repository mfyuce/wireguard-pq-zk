#!/bin/bash
# Fetch the software artefact of PQ-WireGuard (Huelsing, Ning, Schwabe, Weber,
# Zimmermann, IEEE S&P 2021) and unpack it into vagrant/artifacts/. Runs on the
# host. The archive is checked against the digest recorded on 2026-09-29.
set -euo pipefail

ARCHIVE="pqwireguard-20200402.tar.bz2"
SHA256="89a11d24c73bae8b8c1a77e0413c9c19f2e182530a79822b8a19c65c3b2021ba"
URL="https://cryptojedi.org/crypto/data/${ARCHIVE}"
OUT="$(cd "$(dirname "$0")" && pwd)/artifacts"

mkdir -p "$OUT"
cd "$OUT"
if [ ! -f "$ARCHIVE" ]; then
    curl -fsSL -o "$ARCHIVE" "$URL"
fi
echo "${SHA256}  ${ARCHIVE}" | sha256sum -c -
rm -rf pqwireguard-20200402
tar xjf "$ARCHIVE"
ls pqwireguard-20200402
