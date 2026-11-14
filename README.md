# epicmail

An Epicbox-compatible relay for Epic Cash wallets, in one static binary with SQLite inside.

Epic Cash transactions are built interactively: the sender's wallet and the receiver's wallet
pass a transaction file (a *slate*) back and forth before it reaches the chain. When the two
wallets are not online at the same time, they need a mailbox in between. Epicbox is that
mailbox: a relay that holds encrypted slates until the receiving wallet collects them.

epicmail is a relay that speaks the Epicbox protocol, so existing wallets use it without any
change. It is meant for anyone who wants to run one: a public relay for wallet users, a private
relay for an exchange, a pool or a payment service, or a relay for a test network.

## Why another relay

- **One process, no database server.** The store is an embedded SQLite file. There is nothing
  else to install, back up or keep in sync.
- **Durable delivery.** A sender gets `Ok` only after its slate is committed to disk. A slate
  waits until the receiver acknowledges it, or until the retention period ends (7 days by
  default). A receiving socket that drops mid-delivery does not lose the slate.
- **Compatible.** Websocket protocol 2.0.0, 3.0.0 and the 3.1.0 transaction cancel, with the
  frames, error texts, address grammar and signature checks of the original relay. Signature
  checking is tested against the original verifier on recorded cases.
- **Bounded.** Rate limits and caps per IP prefix, per address, per socket and per mailbox, so
  one client cannot exhaust the relay.
- **Observable.** Prometheus metrics, liveness and readiness endpoints, a public status
  document.
- **Extensions that classic wallets never see.** `mux/1` (many mailboxes on one socket) and an
  HTTPS pull API for clients that cannot hold a websocket open.

## How it works

```
 sender wallet                    epicmail                       receiver wallet
      |  PostSlate (signed)          |                                 |
      |----------------------------->|  check limits, address,         |
      |                              |  signature; commit to SQLite    |
      |<---------------- Ok ---------|                                 |
      |                              |-------- Slate (pushed) -------->|
      |                              |<------- Made (signed) ----------|
      |                              |  delete the slate               |
```

1. **Post.** A wallet sends `PostSlate` over a websocket (or `POST /v1/post`). The relay checks
   the rate limits, the sizes, both addresses and the sender's signature over the slate, then
   reads the destination from inside the signed slate.
2. **Store.** If the destination is this relay, the slate is committed to SQLite. If it is
   another relay and federation is on, it is committed to a forward queue instead. Either way,
   the sender gets `Ok` only after the commit.
3. **Deliver.** The receiving wallet proves its key by signing a challenge (`Subscribe`). The
   relay pushes waiting slates to it, one at a time on a classic socket. A delivered slate is
   leased, not deleted, so a socket that dies does not lose it.
4. **Acknowledge.** The wallet answers with `Made` (signed over the message id) and the relay
   deletes the slate. Slates nobody collects expire after `store.retention_days`.

A single writer thread owns the database and commits pending writes in groups, so many posts
share one fsync. On an 8-core desktop with an NVMe disk, one relay held 2,000 messages per
second end to end (stored, delivered, acknowledged, deleted) with p99 latency under 100 ms, and
an idle socket cost about 15 KiB of memory. See [docs/loadtest.md](docs/loadtest.md) for the
method and the limits of that measurement.

[docs/architecture.md](docs/architecture.md) describes the modules, the message flow,
federation, group commit and the background tasks in detail.

## Build

Rust 1.85 or newer.

```sh
cargo build --release
# binary: target/release/epicmail
```

For a static Linux binary (musl), which runs on any x86_64 Linux host:

```sh
tools/build-static.sh
# binary: target/x86_64-unknown-linux-musl/release/epicmail
```

Or build the container image (static binary on a `scratch` base, runs as an unprivileged user):

```sh
docker build -t epicmail .
```

## Run locally

Only `server.domain` is required: the domain wallets write in their addresses for this relay.

```sh
cp packaging/epicmail.example.toml epicmail.toml
# edit epicmail.toml: set server.domain, e.g. "relay.example.org"
target/release/epicmail check-config --config epicmail.toml
target/release/epicmail selftest     --config epicmail.toml
target/release/epicmail serve        --config epicmail.toml
```

By default it listens on `127.0.0.1:3423` and stores data in `epicmail.db` in the working
directory. Check that it is up and that the store is writable:

```sh
curl -fsS http://127.0.0.1:3423/health
curl -fsS http://127.0.0.1:3423/ready
```

To point a wallet at a local relay, set its Epicbox domain to `localhost`, its port to `3423`
and turn off TLS for Epicbox in the wallet's settings.

## Run in production

The relay does not terminate TLS. Put a reverse proxy in front of it and run it under a
supervisor. Everything below is covered step by step in [docs/operating.md](docs/operating.md).

1. **Binary and config.** Install the binary as `/usr/local/bin/epicmail` and the config as
   `/etc/epicmail/epicmail.toml`, with `store.path = "/var/lib/epicmail/epicmail.db"` and
   `server.trusted_proxies` listing the proxy (usually `["127.0.0.1/32"]`).
2. **systemd.** `packaging/epicmail.service` runs the relay as a dynamic, unprivileged user with
   a hardened sandbox, a state directory and a file limit that fits `limits.max_sockets`.

   ```sh
   install -m 0644 packaging/epicmail.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now epicmail
   ```

3. **Reverse proxy.** `packaging/nginx.example.conf` and `packaging/Caddyfile.example` pass the
   websocket upgrade, keep connections open for an hour (wallets hold sockets that long), set
   `X-Forwarded-For` to the client address and keep `/metrics` private.
4. **Docker** instead of systemd:

   ```sh
   docker run -d --name epicmail --restart on-failure \
     -p 127.0.0.1:3423:3423 \
     -v epicmail-data:/data \
     -v /etc/epicmail/epicmail.toml:/etc/epicmail/epicmail.toml:ro \
     epicmail
   ```

   In the container config set `server.listen = "0.0.0.0:3423"` and
   `store.path = "/data/epicmail.db"`.
5. **Monitoring.** Scrape `/metrics` from loopback (or set `server.metrics_listen`), probe
   `/ready`, and back up the database with `sqlite3 ... ".backup ..."` (see the operating guide).

Commands:

| Command | What it does |
|---|---|
| `epicmail serve` | Run the relay. |
| `epicmail check-config` | Load and validate the config, print it, exit. |
| `epicmail selftest` | Check signatures and that the store is writable, exit. |
| `epicmail export [--out FILE]` | Write waiting messages and queued forwards as JSON Lines (read only). |
| `epicmail import FILE` | Load messages from JSON Lines, skipping ones already present. |

All take `--config FILE` (default `/etc/epicmail/epicmail.toml`). `tools/export-node-pg.py`
exports the queue of a Postgres-backed Epicbox relay in the same format, for moving to epicmail.

## Configuration

One TOML file. Every setting except `server.domain` has a default, unknown keys are refused, and
`check-config` validates a file before you restart. The full list, with defaults and a comment
on each line, is [packaging/epicmail.example.toml](packaging/epicmail.example.toml); the
reference is `src/config.rs`.

| Section | Holds |
|---|---|
| `[server]` | Listener, identity (`domain`, `port`, `aliases`), trusted proxies, metrics listener, drain time |
| `[store]` | Database path, retention, size cap, group commit size, reader connections, vacuum hour |
| `[protocol]` | Challenge interval, version answered to `GetVersion`, cancel and mux/1 switches, ping and idle timeouts |
| `[limits]` | Frame and slate sizes, rates per IP prefix and per address, socket caps, mailbox caps, mux/1 and `/v1` budgets |
| `[federation]` | Forwarding to other relays: on/off, allow and deny lists, timeouts |
| `[http_api]` | The `/v1` HTTPS API: on/off, batch sizes, long-poll time and how many may wait at once, challenge window, lease |
| `[log]` | `text` or `json`, and a log filter (the `RUST_LOG` variable overrides it) |

Per-IP limits apply per network prefix (`/24` for IPv4, `/48` for IPv6). List addresses many
users share, such as a Tor onion service's local address, in `limits.shared_sources` so they get
a larger budget.

## Protocols and API

### Epicbox websocket (2.0.0, 3.0.0, 3.1.0)

Wallets connect with a websocket to any path. The relay sends a `Challenge`; a wallet proves a
mailbox by signing it in `Subscribe`, posts with `PostSlate`, receives `Slate` frames and
acknowledges them with `Made`. Version 3.1.0 adds a stable transaction id to `PostSlate`, and
`CancelTx`, which removes every waiting state of a transaction and tells the other party with
`TransactionCancelled`. Signatures are secp256k1 ECDSA over SHA-256 of the UTF-8 text, as DER
hex. Addresses are `[epicbox://]<base58check public key>[@domain[:port]]`.

### mux/1

An opt-in extension: a wallet sends `ClientDetails` with `"ext":["mux/1"]` and then carries any
number of mailboxes on one socket, with several messages in flight, signature-free `Ack`, `Hold`
for messages it cannot handle yet, and a resume token for reconnecting without signing again.
Classic wallets never see a mux/1 frame. The specification is [docs/mux-1.md](docs/mux-1.md).

### HTTPS pull API (`/v1`, `epicbox-https/0.1`)

For clients that cannot hold a websocket. A client makes its own challenge,
`ebh-<unix seconds>-<random lowercase hex>`, and signs it with the mailbox key; each challenge
is accepted once and only inside `http_api.challenge_window_s`.

| Endpoint | Body | Answer |
|---|---|---|
| `GET /v1/info` | | Protocol name, identity, challenge format, limits |
| `POST /v1/post` | A `PostSlate` object without `type` | `{"ok":true,"id":...}`; 400, 409 (cancelled), 429 (rate limit with `Retry-After`, or mailbox full) or 503 |
| `POST /v1/pull` | `{"mailboxes":[{"address","challenge","signature"}],"limit":20,"wait":0..25}` | Waiting messages per mailbox; with `wait`, a long poll that returns when mail arrives |
| `POST /v1/made` | `{"address","acks":[{"id","signature"}]}`, each signature over the id | `{"removed":n,"refused":n}` |

Pulled messages are leased for `http_api.lease_s` seconds and offered again if not acknowledged.
A long poll returns as soon as mail for one of its mailboxes is stored. One prefix may have
`http_api.max_waiting_per_ip` long polls waiting at once (64 by default); more get 429 with
`Retry-After`, while pulls with `wait: 0` are not affected.

### Other HTTP endpoints

| Path | Use |
|---|---|
| `/health` | Liveness: the process answers. |
| `/ready` | Readiness: the store is writable (checked at most every 5 s). 503 while draining. |
| `/metrics` | Prometheus text, names start with `epicbox_`. Only to loopback requests without `X-Forwarded-For`, or on `server.metrics_listen`. |
| `/status.json` | Public totals: sockets, waiting messages, uptime. No per-address data. |
| `/.well-known/epicbox.json` | Software, version, identity, protocol versions, federation, features and their limits. |

### Federation

A slate whose destination is another relay's domain is queued and forwarded to that relay over
`wss://`, with retries and exponential backoff for up to the retention period. Peer names are
resolved by the relay and private, loopback and other special addresses are refused, so a
crafted destination cannot make the relay connect to internal services. `federation.allow`
restricts forwarding to listed relays; `federation.enabled = false` turns it off.

## Security

- **Report vulnerabilities privately**, through the repository's private vulnerability
  reporting, not in a public issue.
- **What the relay can and cannot see.** Slates are encrypted by the wallets for the receiver;
  the relay stores and forwards ciphertext. It does see metadata: sender and receiver addresses,
  sizes, timing and client IP addresses. A mux/1 socket also shows which mailboxes belong
  together. Operators should treat the database and the proxy logs as private.
- **Logs and metrics** carry no addresses, keys, IPs, tokens or payloads. The proxy's access
  log does carry client IPs; configure it to your privacy policy.
- **Authentication.** Reading or acknowledging a mailbox needs a signature by its key: over a
  relay challenge (websocket `Subscribe`, mux/1 `Attach`), over a single-use client challenge
  (`/v1`), or over the message id (`Made`). A mux/1 socket that proved a mailbox may then `Ack`
  without signatures, and its resume token (a bearer secret, valid 24 hours, single use) takes
  the mailboxes back after a reconnect. Failed signatures are rate-limited per IP prefix.
- **Every challenge is random.** The original relay sends one fixed challenge on every new
  socket, so a wallet's first `Subscribe` signature never expires, and anyone who has seen it
  (the operator of any relay that sends the fixed value, for one) could replay it to collect
  that mailbox. epicmail sends a fresh random challenge on every socket and every round, and
  accepts no signature over the fixed value. Wallets older than 3.5.2 always sign the fixed
  value, so they cannot receive through epicmail; they can still post. A replayed signature is
  byte for byte what an old wallet sends, so the two cannot be told apart safely.
- **Trusted proxies.** `X-Forwarded-For` is honoured only from addresses in
  `server.trusted_proxies`. List only your own proxy there, and make the proxy replace the
  header rather than append to it (the examples do).
- **Keep private:** `/metrics` (the proxy examples return 404 for it) and the test switch
  `test.stall_endpoint`, which must stay off on a public relay.
- **Resource limits.** Every input is bounded: frame and slate size, frames per socket, posts
  and bytes per IP prefix and per address, sockets per prefix and in total, waiting messages per
  mailbox and per sender, mux/1 mailboxes and in-flight messages, `/v1` work per prefix, waiting
  `/v1` long polls per prefix and in total, and the memory held by mux/1 resume tokens. A socket whose client stops reading is closed after
  `protocol.idle_timeout_s`.
- **Sandbox.** The systemd unit runs with a dynamic user, no capabilities, a read-only system,
  a private `/tmp` and a system call filter. The container runs as an unprivileged user on an
  empty base image.

## Contributing

Issues and pull requests are welcome. Before sending a change:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo test` runs the unit tests, `tests/loopback.rs` (relays on loopback ports, driven over
websocket and HTTP, including federation between two relays) and the signature differential
test against recorded cases ([tools/sigdiff/README.md](tools/sigdiff/README.md)).
`tools/compat-classic.sh` runs real classic wallets against two local relays; its header lists
what it needs.

Some guidance:

- Keep wire compatibility. A classic wallet must never receive a frame it cannot parse, and the
  error texts match the original relay. mux/1 is frozen; a wire change needs a new version.
- Add a test with each fix, preferably one that fails without it.
- Keep commits small, with a subject of the form `Area: what changed` and the reason in the
  body.
- Never log addresses, keys, tokens, IPs or payloads, and never put them in metric labels.

### Source map

| Path | What it does |
|---|---|
| `src/main.rs` | CLI, startup, housekeeping, shutdown |
| `src/config.rs` | Configuration file, defaults and checks |
| `src/http/` | HTTP routes and the websocket upgrade (`mod.rs`), the `/v1` API (`v1.rs`) |
| `src/relay/` | Shared state, posting, cancel, resume tokens, the socket registry and the websocket sessions |
| `src/store/` | The `Store` trait and the SQLite store |
| `src/forward.rs` | Forwarding to other relays |
| `src/limits.rs` | Rate limits and socket counts |
| `src/address.rs`, `src/sig.rs` | Epicbox addresses and signatures |
| `src/bus.rs`, `src/metrics.rs` | Post-commit events, Prometheus metrics |
| `src/migrate.rs` | JSON Lines import and export |
| `src/clock.rs`, `src/ids.rs` | Wall-clock milliseconds, random ids and id checks |
| `examples/loadgen.rs` | Load generator used for docs/loadtest.md |
| `src/bin/sigdiff-gen.rs`, `tests/sigdiff.rs` | Signature differential test |
| `packaging/` | systemd unit, nginx and Caddy examples, example config |
| `tools/` | Static build, classic wallet compatibility run, export from Postgres-backed relays |

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
