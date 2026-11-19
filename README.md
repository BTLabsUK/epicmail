<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/epicbox-icon-dark.svg">
  <img src="docs/assets/epicbox-icon-light.svg" alt="Epicbox" width="96" height="96">
</picture>

# EPICMAIL

**An Epicbox relay for Epic Cash wallets: one Rust binary, SQLite inside, no wallet changes.**

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV 1.100](https://img.shields.io/badge/rust-1.100-orange.svg)](rust-toolchain.toml)
[![Version](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2FBTLabsUK%2Fepicmail%2Fmain%2FCargo.toml&query=%24.package.version&label=version&color=informational)](Cargo.toml)
[![Epicbox 2.0.0 · 3.0.0 · 3.1.0](https://img.shields.io/badge/epicbox-2.0.0%20%C2%B7%203.0.0%20%C2%B7%203.1.0-6f42c1.svg)](#protocols)

[Run a relay](#run-a-relay) · [Build](#build-from-source) · [Operating](docs/operating.md) ·
[Architecture](docs/architecture.md) · [mux/1](docs/mux-1.md) · [Security](#security)

</div>

Epic Cash wallets build a transaction together: the sender's and the receiver's wallets pass a
*slate* back and forth before it goes on chain. When the two are not online at the same time, an
Epicbox relay holds the encrypted slate until the receiver collects it.

epicmail is that relay. It speaks the same websocket protocol as the existing Epicbox relays,
federates with them, and serves today's wallets unchanged. A sender gets `Ok` only after its
slate is on disk, every input has a limit, and logs never hold full keys, slates or signatures.

Status: early release. The Epicbox protocol support is complete and mux/1 is frozen;
the `/v1` HTTPS API may change before 1.0.

## Shape

| Part | What it is | Where |
|---|---|---|
| Relay | `epicmail serve`: the Epicbox websocket protocol, federation, health and metrics | [`src/`](#project-structure) |
| Store | One SQLite file with a single writer and group commit | [Architecture](docs/architecture.md#group-commit) |
| mux/1 | Opt-in: many mailboxes on one socket, for services | [Specification](docs/mux-1.md) |
| `/v1` | Opt-in: an HTTPS pull API for clients that cannot hold a socket | [HTTPS pull API](#https-pull-api-v1) |
| Tools | Config check, self test, JSON Lines import and export, a static build | [Commands](#commands) |

```
 sender wallet                    epicmail                       receiver wallet
      |  PostSlate (signed)          |                                 |
      |----------------------------->|  limits, address and signature  |
      |                              |  checks; commit to SQLite       |
      |<---------------- Ok ---------|                                 |
      |                              |-------- Slate (pushed) -------->|
      |                              |<------- Made (signed) ----------|
      |                              |  delete the slate               |
```

## Run a relay

On a Linux server with systemd (x86_64 or aarch64), point a domain at the machine, open ports 80
and 443, and run:

```sh
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh -s -- --domain relay.example.org
```

It downloads the latest release binary for the machine, checks it with `minisign` (required) against the release's signed
`SHA256SUMS`, installs the relay as a hardened systemd service with its config in
`/etc/epicmail/epicmail.toml`, and installs Caddy for TLS. Wallets then use Epicbox domain
`relay.example.org`, port 443. Run the same command again to upgrade (without `--domain`: `curl -fsSL .../tools/get.sh | sh`): it backs up the store,
checks the config with the new binary and restarts only when something changed.

- `--version X.Y.Z` installs a given release instead of the latest.
- `--no-tls` skips Caddy, for a server with its own proxy. An nginx, Caddy or Apache already on
  the machine is never changed; the script prints the site to add instead.
- `--uninstall` removes the service and binary and keeps config and data.

Releases are signed with [minisign](https://jedisct1.github.io/minisign/). The script
needs `minisign`: without it, it stops and says so, and there is no way to skip the check. It
checks the signature, then the binary, `tools/install.sh` and the packaging files it installs
against the signed `SHA256SUMS`, and refuses anything that fails. To check a download by hand:

```sh
minisign -Vm SHA256SUMS -P RWQ+swweZiIFJfbre/aOhYqQ1+82BHFnw8gF6ETbhCp5b7RB6RuMEVtP
sha256sum -c --ignore-missing SHA256SUMS
```

### By hand

From a checkout, `tools/install.sh` does the same install with a binary built from source, or
with one built elsewhere (`--bin FILE`); `--help` lists its options. Then put a TLS proxy in
front: `packaging/Caddyfile.example` or `packaging/nginx.example.conf`.

```sh
tools/install.sh --domain relay.example.org
```

To install a release binary by hand, download it with `SHA256SUMS`, check it, and mark it
executable: a downloaded file never keeps the executable bit.

```sh
a=x86_64   # or aarch64
v=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/BTLabsUK/epicmail/releases/latest)
v=${v##*/v}   # the latest release
base=https://github.com/BTLabsUK/epicmail/releases/download/v$v
curl -fsSLO $base/epicmail-$v-linux-$a -O $base/SHA256SUMS -O $base/SHA256SUMS.sig
minisign -Vm SHA256SUMS -P RWQ+swweZiIFJfbre/aOhYqQ1+82BHFnw8gF6ETbhCp5b7RB6RuMEVtP
sha256sum -c --ignore-missing SHA256SUMS
chmod +x epicmail-$v-linux-$a
tools/install.sh --bin epicmail-$v-linux-$a --domain relay.example.org
```

A `get.sh` saved to disk runs with `sh get.sh ...`, no `chmod` needed.

[packaging/production/](packaging/production/) shows a real deployment on top of that: an old
relay name kept as an alias, an optional federation allow list, a Tor onion service, and a fixed
service user.

Docker: `docker build -t epicmail .` makes an image on an empty base;
[docs/operating.md](docs/operating.md#docker) shows how to run it. The operating guide also covers
limits, health checks, backup, logging and upgrades.

### Try it locally

You need Rust through `rustup`; it installs the pinned 1.100 from `rust-toolchain.toml`.

```sh
cargo build --release
cp packaging/epicmail.example.toml epicmail.toml     # set server.domain
target/release/epicmail serve --config epicmail.toml
curl -fsS http://127.0.0.1:3423/ready
```

It listens on `127.0.0.1:3423` and keeps its data in `epicmail.db`. To try it with a wallet, set
the wallet's Epicbox domain to `localhost`, port `3423`, with TLS off.

## Build from source

```sh
cargo build --release                 # target/release/epicmail
tools/build-static.sh                 # static x86_64 Linux binary (musl)
docker build -t epicmail .            # static binary on an empty base, unprivileged user
```

### Commands

| Command | What it does |
|---|---|
| `epicmail serve` | Run the relay. |
| `epicmail check-config` | Load and validate the config, print it, exit. |
| `epicmail selftest` | Check signing, verification and that the store is writable, exit. |
| `epicmail export [--out FILE]` | Write waiting messages and queued forwards as JSON Lines (read only). |
| `epicmail import FILE` | Load messages and forwards from JSON Lines; repeatable, duplicates are skipped. |

All take `--config FILE` (default `/etc/epicmail/epicmail.toml`).

## Testing

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

`cargo test` runs the unit tests, relays on loopback ports driven over websocket and HTTP (with
federation between two relays), a log privacy check of both log outputs at trace level, and a
signature differential
test against cases recorded from the original verifier ([tools/sigdiff](tools/sigdiff/README.md)).
`tools/compat-classic.sh` runs the real wallet CLI against two local relays; its header lists what
it needs.

## Compatibility

| | |
|---|---|
| Wallet changes | None. Point the wallet's Epicbox domain and port at the relay. |
| Protocol versions | 2.0.0, 3.0.0 and 3.1.0 (transaction cancel); pre-2.0.0 wallets too. |
| Other relays | Federates both ways. Cancels pass both ways with the reference 3.1.0 relay. |
| Addresses | `[epicbox://]<base58check public key>[@domain[:port]]`, port 443 by default. |
| Signatures | secp256k1 ECDSA over SHA-256 of the text, strict DER, low-S. |
| Wallets before 3.5.2 | Can post, cannot receive: they sign a fixed first challenge, which epicmail refuses ([why](#security)). |
| Migration | `tools/export-node-pg.py` exports a Postgres-backed relay's queue; `epicmail import` loads it. |

## Protocols

### Epicbox websocket

A wallet connects, gets a `Challenge`, proves its mailbox by signing it in `Subscribe`, posts
with `PostSlate`, receives `Slate` frames and acknowledges each with `Made`.

| | 2.0.0 | 3.0.0 | 3.1.0 |
|---|---|---|---|
| `Made` signed over | the current challenge | the message id | the message id |
| `Slate` carries | `epicboxmsgid`, `ver` | `epicboxmsgid`, `ver` | also `epicboxtxid` |
| Cancel | no | no | `CancelTx`, `TransactionCancelled` |

What a wallet may notice, all within what wallets already accept:

- Every challenge is random, the first one included.
- A delivered slate is leased for 60 s, not held until `Made`. A slate one wallet keeps failing on
  steps aside after three tries.
- A socket that ignores three challenges while mail waits is closed with 1001, so the wallet
  reconnects.
- A malformed frame closes only its own socket.

### mux/1

A client sends `ClientDetails` with `"ext":["mux/1"]`, then carries many mailboxes on one socket,
each proven once with `Attach`. It gets several messages in flight, signature-free `Ack`, `Hold`,
`Waiting` counts and a resume token. Classic wallets never see it.
[docs/mux-1.md](docs/mux-1.md) is the specification.

### HTTPS pull API (`/v1`)

For clients that cannot hold a websocket. The client makes its own challenge,
`ebh-<unix seconds>-<random hex>`, and uses it once. It signs `<challenge>@<identity>` with the mailbox
key, where identity is the relay's `domain:port` as `GET /v1/info` shows it, so a proof made for one
relay is refused by any other. Plain `<challenge>` is not accepted.

| Endpoint | Does |
|---|---|
| `GET /v1/info` | Protocol name, identity, challenge format, limits |
| `POST /v1/post` | Post a slate (`PostSlate` without `type`) |
| `POST /v1/pull` | Collect waiting messages; `wait` makes it a long poll |
| `POST /v1/made` | Acknowledge messages, each signature over the id |

### Health and metadata

| Path | Use |
|---|---|
| `/health` | Liveness |
| `/ready` | Readiness: the store is writable; 503 while draining |
| `/metrics` | Prometheus, names start with `epicbox_`; loopback or `server.metrics_listen` only |
| `/status.json` | Public totals, no per-address data |
| `/.well-known/epicbox.json` | Software, identity, protocols, features (mux/1, `txcancel/1`, `epicbox-cancel/1`, https) and client limits (no version, no per-IP limits) |
| `/` in a browser | A page for people: what the relay is, live checks, the domain and port for a wallet (`server.landing_page`) |

## Transaction cancel (3.1.0)

A 3.1.0 `PostSlate` carries `epicboxtxid` and the sender's signature over it. A participant can
later send `CancelTx`, signed over the bare txid as wallets sign it today, or over
`epicbox-cancel/1:<txid>`.

- Every waiting state of the transaction is deleted, and a cancel record is kept for the
  retention period. A later post with the same txid gets `TransactionCancelled` instead of `Ok`.
- The receiver gets `TransactionCancelled` pushed, or on its next `Subscribe` if offline.
- A non-participant gets a plain `Ok`, so the answer does not reveal whether the transaction
  exists.
- The cancel is forwarded to every other relay that holds states of the transaction, with a
  `cancelrequestid` that ends loops.
- The record, the deletions and the queued forwards are stored in one transaction: all of it or
  none.

The bare-txid signature is the one the slate already carried, so anyone who saw the slate can
cancel. `epicbox-cancel/1:<txid>` closes that; `protocol.forward_bare_cancel = false` forwards
only that form, and `protocol.accept_bare_cancel = false` accepts only that form (both on by
default, since stock wallets sign the bare txid). `protocol.cancel = false` makes the relay a
3.0.0 relay.

A relay that has the cancel on offers the separated form to wallets in band: a client lists
`epicbox-cancel/1` in `ClientDetails.ext`, and the `Ok` repeats it (on a classic socket as
`{"type":"Ok","ext":["epicbox-cancel/1"]}`, on mux/1 among the other extensions). The relay also
lists it as a feature in `/.well-known/epicbox.json`. It verifies the separated form first and the
bare form second on every path, and forwards the signature as it received it. The exact text and
the fallback are in [docs/cancel-signature.md](docs/cancel-signature.md).

A mux/1 Attach can be bound to the relay's name the same way: a client lists `epicbox-attach/1`,
and on a socket where it is echoed each entry names the host it dialled and signs
`epicbox-attach/1:<host>:<challenge>`. The relay refuses a host that is not `server.domain` or an
alias with `wrong_host`, logs the first one of a socket at `info` and counts it in
`epicbox_attach_wrong_host_total`; it is not a failed signature, so the client's bare retry is
not rate-limited. The bare-challenge form stays accepted while
`protocol.accept_bare_attach` is on (the default); list every name wallets dial, onion included,
in `server.aliases` before turning it off. Details in [docs/mux-1.md](docs/mux-1.md) section 9.

## Federation

A slate for another relay's domain is queued and forwarded over `wss://`, as a wallet would post
it. The relay resolves the peer itself, refuses private and special addresses, and checks the
certificate against the peer's domain, so a crafted destination cannot reach internal services.
Failed deliveries back off from 5 s to 1 hour per peer. `federation.allow`, `deny` and `peers`
control where slates go; `federation.enabled = false` turns forwarding off.

## Configuration

One TOML file. Every setting except `server.domain` has a default, and unknown keys and invalid
values are refused at load.
[packaging/epicmail.example.toml](packaging/epicmail.example.toml) lists every setting with its
default; `src/config.rs` is the reference.

| Section | Holds |
|---|---|
| `[server]` | Listener, identity (`domain`, `port`, `aliases`), trusted proxies, metrics listener, drain |
| `[store]` | Database path, retention, size cap, group commit, readers, vacuum hour |
| `[protocol]` | Challenge interval, `GetVersion` answer, cancel and mux/1 switches, timeouts, watchdog |
| `[limits]` | Sizes, rates per network prefix and per sender, socket and mailbox caps |
| `[federation]` | Forwarding on or off, allow and deny lists, peer URLs, timeouts |
| `[http_api]` | The `/v1` API: on or off, batch sizes, long polls, challenge window, lease |
| `[log]` | Level and format of stderr (`RUST_LOG` overrides the level), the traffic summary, and `[log.file]`: a second output with its own level, rotated, compressed and pruned by the relay |

Per-IP limits apply per network prefix (`/24` for IPv4, `/48` for IPv6). `server.trusted_proxies`
must list the reverse proxy, or every client counts as the proxy. Sources many users share, such
as a Tor service, go in `limits.shared_sources`.

## Data and privacy

| Data | Kept until |
|---|---|
| Waiting slate | Acknowledged, or `store.retention_days` after posting (default and minimum 7) |
| Queued forward | Delivered, refused three times, or the retention period |
| Cancel record | The retention period |
| mux/1 resume token, rate-limit state | Memory only |

The store holds what delivery needs: ciphertext slates, addresses, signatures, timestamps and
delivery counts. It holds no client IPs. Deleted slates are overwritten where that costs no extra
I/O, and `store.max_bytes` caps the live data.

**Logs.** stderr (the journal) is at `info` by default and names no client: it holds the
startup line, a traffic summary every five minutes in counts only (when anything changed),
expiry sweeps, forwards per peer relay and problems. The log file, **on by default**
(`/var/log/epicmail/epicmail.log` at `trace`, rotated daily, compressed, 14 days kept), and
stderr at `debug` or `trace` hold **client IP addresses and shortened addresses** (the first and
last six characters of the key, plus the domain), message ids and timing: personal data, to be
kept short and private. To log no IPs, set `[log.file] enabled = false` and keep `log.level` at
`info`; to keep them for less time, lower `log.file.keep` or journald's `MaxRetentionSec`
([docs/operating.md](docs/operating.md#8-logging)). A relay that cannot write the file logs a
warning and runs without it. No level ever logs full
keys, slates, signatures, challenges or resume tokens. Metric labels carry outcomes and limit
names only.

## Security

- **Ciphertext only.** Wallets encrypt slates; the relay cannot read, forge or alter one. It does
  see metadata (addresses, sizes, timing, client IPs on connections), so keep the database and
  the proxy's access log private.
- **Random challenges.** The original protocol sends one fixed first challenge, so a first
  `Subscribe` signature never expires and can be replayed. epicmail never sends or accepts it.
  A replay and an old wallet's signature are the same bytes, which is why wallets before 3.5.2
  cannot receive here.
- **Bounded input.** Frame and slate sizes, posts, bytes, sockets, mailbox sizes and signature
  checks are all limited; a client that stops reading is disconnected. Defaults are in
  [docs/operating.md](docs/operating.md#3-limits).
- **Sandbox.** The systemd unit runs with a dynamic user, no capabilities and a system call
  filter; the container runs unprivileged on an empty base.
- **Dependencies.** `cargo deny` fails on any RustSec advisory, non-permissive licence or
  OpenSSL; TLS is rustls, signatures use the `secp256k1` crate.

Report vulnerabilities through the repository's private vulnerability reporting, not in a public
issue.

## Known limits

- **One node.** SQLite with one writer, one process, no clustering. A standby restored from
  backup covers most needs; [docs/operating.md](docs/operating.md#7-when-to-switch-to-postgres)
  says when it stops being enough.
- **No TLS of its own.** It expects a reverse proxy in front.
- **Per-prefix limits are coarse.** Users behind one carrier NAT share a budget unless their
  source is in `limits.shared_sources`.
- **Cancel authority** follows the protocol: a bare-txid cancel can come from anyone who saw the
  slate.
- **Export** does not carry cancel records.
- **mux/1 and `/v1` are epicmail's own.** Clients that use them should fall back to the classic
  protocol on other relays.

## Project structure

| Path | Contents |
|---|---|
| `src/main.rs`, `src/config.rs` | CLI, startup, shutdown; configuration and its checks |
| `src/http/` | HTTP routes, the websocket upgrade and the `/v1` API |
| `src/relay/` | Shared state, posting, cancel, resume tokens, socket registry, sessions |
| `src/store/` | The `Store` trait and the SQLite store |
| `src/forward.rs` | Forwarding to other relays |
| `src/limits.rs` | Rate limits and socket counts |
| `src/address.rs`, `src/sig.rs` | Epicbox addresses and signatures |
| `src/logging.rs`, `src/metrics.rs`, `src/traffic.rs` | Log helpers, Prometheus metrics, the log's traffic summary |
| `src/migrate.rs` | JSON Lines import and export |
| `tests/` | Loopback relays, log privacy, signature differential |
| `examples/` | Traffic generators and checks for a running relay |
| `packaging/` | systemd unit, nginx and Caddy examples, example config |
| `tools/` | One-line installer (`get.sh`), install script, static build, classic wallet run, export from Postgres-backed relays |

## Documentation

- [Operating](docs/operating.md): install, limits, health, backup, logging, upgrade
- [Architecture](docs/architecture.md): modules, message flow, group commit, background tasks
- [mux/1 specification](docs/mux-1.md)
- [Example configuration](packaging/epicmail.example.toml)

## Contributing

Issues and pull requests are welcome. Every change passes the four commands under
[Testing](#testing) and keeps wire compatibility: a classic wallet must never get a frame it
cannot parse, and error texts match the original relay. Add a test with each fix, keep commits
small (`Area: what changed`), and log through the helpers in `src/logging.rs`.

## License

Apache License 2.0, see [LICENSE](LICENSE).
