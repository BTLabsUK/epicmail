#!/bin/sh
# Build the static x86_64 musl binary. Output: target/x86_64-unknown-linux-musl/release/epicbox-relay
set -eu
cd "$(dirname "$0")/.."
T=x86_64-unknown-linux-musl
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$T"; then
  rustup target add "$T"
fi
command -v musl-gcc >/dev/null 2>&1 || echo "warning: musl-gcc not found; rusqlite (bundled SQLite) needs it (apt install musl-tools)" >&2
cargo build --release --locked --target "$T" --bin epicbox-relay
BIN=target/$T/release/epicbox-relay
file "$BIN"
if ldd "$BIN" 2>&1 | grep -Eq 'not a dynamic|statically linked'; then echo "static: yes"; else echo "static: NO" >&2; exit 1; fi
