# epicmail

epicmail is a relay for Epic Cash wallets: it holds encrypted transaction slates until the
receiving wallet collects them. It is compatible with Epicbox, so existing wallets use it without
changes. It is one static binary with SQLite inside.

It is for anyone who wants to run an Epicbox relay: a public relay for wallet users, or a private
one for a service, an exchange or a test network.

## Features

- Epicbox websocket protocol 2.0.0 and 3.0.0, and the 3.1.0 transaction cancel.
- `mux/1`: one websocket holds many mailboxes and has several messages in flight
  ([docs/mux-1.md](docs/mux-1.md)). Classic wallets are not affected.
- An HTTPS pull API under `/v1` for clients that cannot hold a websocket.
- Federation: mail for another relay's domain is queued and forwarded to it.
- Durable delivery: a wallet gets `Ok` only after the message is committed. Messages wait up to
  `store.retention_days` (7 by default) and are deleted when the receiver acknowledges them.
- Rate limits and caps per IP prefix, per address, per socket and per mailbox.
- Prometheus metrics, health and readiness endpoints, a status document.
- Import and export of queued messages as JSON Lines, for moving from another relay.

## Quick start

Build (Rust 1.85 or newer):

```sh
cargo build --release
```

`tools/build-static.sh` builds a static musl binary instead.

Configure. Only `server.domain` is required; every other setting has a default:

```sh
cp packaging/epicmail.example.toml epicmail.toml
# set server.domain to the domain wallets write in their addresses, e.g. relay.example.org
target/release/epicmail check-config --config epicmail.toml
target/release/epicmail selftest --config epicmail.toml
```

Run:

```sh
target/release/epicmail serve --config epicmail.toml
```

Check that it is up and that the store is writable:

```sh
curl -fsS http://127.0.0.1:3423/health
curl -fsS http://127.0.0.1:3423/ready
```

In production, put a reverse proxy that ends TLS in front of it. [docs/operating.md](docs/operating.md)
covers systemd, Docker, the proxy, limits, metrics, backup and retention. `packaging/` holds the
systemd unit and the Caddy and nginx examples.

## Documentation

- [docs/operating.md](docs/operating.md): install, configure and run a relay.
- [docs/architecture.md](docs/architecture.md): how a message moves through the relay, and why.
- [docs/mux-1.md](docs/mux-1.md): the `mux/1` protocol.
- [docs/loadtest.md](docs/loadtest.md): throughput, latency and memory measured on one host.
- [packaging/epicmail.example.toml](packaging/epicmail.example.toml): every setting with its
  default.

## Source map

| Path | What it does |
|---|---|
| `src/main.rs` | CLI, startup, housekeeping, shutdown |
| `src/config.rs` | Configuration file and defaults |
| `src/http.rs` | HTTP routes, websocket upgrade, `/v1` API |
| `src/relay/` | Shared state, posting, cancel, the socket registry and the websocket sessions |
| `src/store/` | The `Store` trait and the SQLite store |
| `src/forward.rs` | Forwarding to other relays |
| `src/limits.rs` | Rate limits and socket counts |
| `src/address.rs`, `src/sig.rs` | Epicbox addresses and signatures |
| `src/bus.rs`, `src/metrics.rs` | Post-commit events, Prometheus metrics |
| `src/migrate.rs` | JSON Lines import and export |
| `examples/loadgen.rs` | Load generator used for docs/loadtest.md |
| `src/bin/sigdiff-gen.rs`, `tests/sigdiff.rs` | Signature differential test ([tools/sigdiff/README.md](tools/sigdiff/README.md)) |
| `tools/` | Static build, classic wallet compatibility run, export from Postgres-backed relays |

## Testing

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`cargo test` runs the unit tests, `tests/loopback.rs` (a relay on a loopback port, driven over
websocket and HTTP) and the signature differential test against recorded cases.

`tools/compat-classic.sh` runs real classic wallets against two local relays: send, receive,
offline delivery and federation. It needs a local Epic network with two funded wallets; the
header of the script lists what it expects.

## Protocols

- Epicbox: the websocket protocol of the stock Epicbox relay, versions 2.0.0, 3.0.0 and the 3.1.0
  cancel. epicmail matches its frames, error texts, address grammar and signature checks.
- [mux/1](docs/mux-1.md): an extension a wallet opts into with `ClientDetails`.
- HTTPS `/v1` (`epicbox-https/0.1`): post, pull and acknowledge over HTTPS. `GET /v1/info` on a
  running relay describes the challenge format and the limits.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
