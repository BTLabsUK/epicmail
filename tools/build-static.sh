#!/bin/sh
# Build a static Linux binary of epicmail against musl, and check that it is static.
#
# Usage: tools/build-static.sh [x86_64|aarch64]   (from any directory; default: this host's arch)
# Needs: rustup (adds the musl target if missing). A native build needs musl-gcc for the bundled
# SQLite (Debian/Ubuntu: apt install musl-tools). A build for the other arch needs cargo-zigbuild
# and zig (cargo install cargo-zigbuild; zig from ziglang.org or pip install ziglang).
# Output: target/<arch>-unknown-linux-musl/release/epicmail
set -eu
cd "$(dirname "$0")/.."

host=$(uname -m)
case $host in amd64) host=x86_64 ;; arm64) host=aarch64 ;; esac
arch=${1:-$host}
case $arch in
  x86_64 | aarch64) ;;
  *) echo "build-static.sh: unknown arch $arch (x86_64 or aarch64)" >&2; exit 2 ;;
esac
T=$arch-unknown-linux-musl

if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$T"; then
  rustup target add "$T"
fi
if [ "$arch" = "$host" ]; then
  command -v musl-gcc >/dev/null 2>&1 || echo "warning: musl-gcc not found; rusqlite (bundled SQLite) needs it (apt install musl-tools)" >&2
  cargo build --release --locked --target "$T" --bin epicmail
else
  command -v cargo-zigbuild >/dev/null 2>&1 || { echo "build-static.sh: building for $arch on $host needs cargo-zigbuild" >&2; exit 1; }
  cargo zigbuild --release --locked --target "$T" --bin epicmail
fi

BIN=target/$T/release/epicmail
file "$BIN"
case $(file -b "$BIN") in
  *"static-pie linked"* | *"statically linked"*) echo "static: yes" ;;
  *) echo "static: NO" >&2; exit 1 ;;
esac
