#!/bin/bash
# Fetch the official release of Rosenpass that the measurements compare with
# and unpack it into vagrant/artifacts/. Runs on the host. The archive is
# checked against the digest recorded here on 2026-09-29.
set -euo pipefail

VERSION="0.2.3"
ARCHIVE="rosenpass-x86_64-linux-${VERSION}.tar"
SHA256="53158a8c339e3be1a9520b91c33a9e83eab05ea49af346cdb7e6eec522f2318b"
URL="https://github.com/rosenpass/rosenpass/releases/download/v${VERSION}/${ARCHIVE}"
OUT="$(cd "$(dirname "$0")" && pwd)/artifacts/rosenpass-${VERSION}"

mkdir -p "$OUT"
cd "$OUT"
if [ ! -f "$ARCHIVE" ]; then
    curl -fsSL -o "$ARCHIVE" "$URL"
fi
echo "${SHA256}  ${ARCHIVE}" | sha256sum -c -
tar xf "$ARCHIVE"
chmod 755 bin/rosenpass bin/rp
bin/rosenpass --version
