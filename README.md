# epicmail

An Epicbox-compatible relay for Epic Cash wallets: one Rust binary with an embedded SQLite
store. Existing wallets use it without any change.

Epic Cash transactions are built interactively. The sender's and the receiver's wallets pass a
transaction file (a *slate*) back and forth before it goes on chain, and when the two are not
online at the same time they need a mailbox in between. An Epicbox relay is that mailbox: it
holds slates, encrypted by the wallets, until the receiver collects them. epicmail speaks the
same websocket protocol as the existing Epicbox relays and federates with them.

This README is for developers, operators and wallet maintainers. It tries to answer the
questions each of them will have; [docs/](docs/) holds the details.

- [Why this relay](#why-this-relay)
- [Compatibility at a glance](#compatibility-at-a-glance)
- [How a slate moves](#how-a-slate-moves)
- [Build and run](#build-and-run)
- [Configuration](#configuration)
- [Protocols](#protocols)
- [Transaction cancel (3.1.0)](#transaction-cancel-310)
- [Federation](#federation)
- [Data and retention](#data-and-retention)
- [Logging and metrics](#logging-and-metrics)
- [Security model](#security-model)
- [Known limits](#known-limits)
- [Questions](#questions)
- [Contributing](#contributing)

## Why this relay

The existing relays work and carry real traffic. epicmail was written to make a relay easy for
anyone to run and to reason about, with these properties stated and tested:

- **Durable delivery.** A sender gets `Ok` only after its slate is committed to disk with
  `fsync`. Delivering a slate leases it instead of deleting it, so a receiver whose connection
  drops mid-delivery gets it again. A slate is deleted when the receiver acknowledges it with a
  signed `Made`, or when the retention period (7 days by default) ends. A slate that one wallet
  cannot handle steps aside after three tries instead of blocking the rest of the mailbox.
- **Bounded resources.** Every input has a limit: frame and slate size, posts and bytes per
  network prefix and per sender, sockets per prefix and in total, mail per mailbox and per
  sender, signature checks per prefix, and the live size of the database. A client that stops
  reading is disconnected instead of holding memory. The limits are listed with their defaults
  in [docs/operating.md](docs/operating.md#3-limits).
- **Compatibility coverage.** The websocket protocol 2.0.0, 3.0.0 and the 3.1.0 transaction
  cancel are implemented frame by frame, with the original error texts and address grammar.
  Signature checking is compared against the original verifier on a recorded corpus of edge
  cases (`tests/sigdiff.rs`), and `tools/compat-classic.sh` runs the real wallet CLI against
  two local relays, including federation between them.
- **Operations.** One static binary and one TOML file; no database server. Health and
  readiness endpoints, Prometheus metrics, a graceful SIGTERM drain, a hardened systemd unit and
  a container image on an empty base. Configuration is validated before start, and unknown keys
  are refused.
- **Privacy by default.** Every challenge is random, so a captured signature cannot be replayed.
  Logs and metrics never hold full addresses, slates, signatures or client IPs, and repeated
  log lines are sampled. Deleted slates are overwritten on disk where that costs no extra I/O.
- **Room to grow without breaking wallets.** Two opt-in extensions, `mux/1` (many mailboxes on
  one socket) and an HTTPS pull API, serve services and clients that cannot hold one socket
  per mailbox. A classic wallet never sees either.

How fast it is depends on the host. One measurement, on a shared 8-core development machine
with an NVMe disk, sustained about 2,000 slates a second end to end (posted, stored,
delivered, acknowledged, deleted) with no loss; an idle subscribed socket cost about 15 KiB of
memory. [docs/loadtest.md](docs/loadtest.md) has the method, the full results and what was not
measured. Measure your own host before relying on these figures.

## Compatibility at a glance

| Question | Answer |
|---|---|
| Wallet changes needed? | None. Point the wallet's Epicbox domain and port at the relay. |
| Protocol versions | 2.0.0, 3.0.0 and 3.1.0 (transaction cancel). Pre-2.0.0 wallets (no `ver` in Subscribe) are served too; their slates are deleted on delivery since they send no `Made`. `GetVersion` answers `protocol.getversion`, `3.1.0` by default. |
| Wallets that sign a fixed first challenge | Versions before 3.5.2 sign the same constant on every new socket. epicmail never sends or accepts it, so these wallets can post through epicmail but cannot receive from it. See [Security model](#security-model). |
| Other relays | Federates both ways with relays that speak the same protocol. It forwards as a wallet would (wait for `Challenge`, send `PostSlate`, read `Ok`), and accepts forwarded slates like any post. Cancels pass both ways with the reference 3.1.0 relay. |
| Addresses | `[epicbox://]<base58check public key>[@domain[:port]]`, the original grammar. Port defaults to 443. |
| Signatures | secp256k1 ECDSA over SHA-256 of the UTF-8 text, strict DER, low-S, hex as the original verifier decodes it. |
| Migrating from a Postgres-backed relay | `tools/export-node-pg.py` exports its queue as JSON Lines; `epicmail import` loads it. |

## How a slate moves

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

1. **Post.** A wallet sends `PostSlate` over a websocket (or `POST /v1/post`). The relay checks
   the rate limits, the sizes, both addresses and the sender's signature over the slate, then
   reads the destination from inside the signed slate.
2. **Store.** If the destination is this relay, the slate is committed to SQLite. If it is
   another relay and federation is on, it is committed to a forward queue instead. Either way
   the sender gets `Ok` only after the commit.
3. **Deliver.** The receiving wallet proves its key by signing a challenge (`Subscribe`). The
   relay pushes waiting slates to it, one at a time on a classic socket, each leased for 60 s.
4. **Acknowledge.** The wallet answers with `Made`, signed over the message id, and the relay
   deletes the slate.

One writer thread owns the database and commits pending writes in groups, so many posts share
one `fsync`. [docs/architecture.md](docs/architecture.md) describes the modules, group commit,
federation and the background tasks.

## Build and run

Rust 1.100 or newer. `rust-toolchain.toml` pins the version the project is tested with, and
rustup picks it up.

```sh
cargo build --release                 # target/release/epicmail
tools/build-static.sh                 # static x86_64 Linux binary (musl)
docker build -t epicmail .            # static binary on an empty base, unprivileged user
```

Run locally. Only `server.domain` is required: the domain wallets write in their addresses.

```sh
cp packaging/epicmail.example.toml epicmail.toml     # set server.domain
target/release/epicmail check-config --config epicmail.toml
target/release/epicmail selftest     --config epicmail.toml
target/release/epicmail serve        --config epicmail.toml
curl -fsS http://127.0.0.1:3423/ready
```

It listens on `127.0.0.1:3423` and stores data in `epicmail.db` by default. To test with a
wallet, set its Epicbox domain to `localhost`, port `3423`, and turn off TLS for Epicbox.

Run in production behind a reverse proxy that ends TLS, under systemd or Docker.
[docs/operating.md](docs/operating.md) covers it step by step: install, the systemd unit
(`packaging/epicmail.service`), nginx and Caddy examples (`packaging/`), limits, health
endpoints, backup and restore, logging, upgrade and roll back.

| Command | What it does |
|---|---|
| `epicmail serve` | Run the relay. |
| `epicmail check-config` | Load and validate the config, print it, exit. |
| `epicmail selftest` | Check signing and verification and that the store is writable, exit. |
| `epicmail export [--out FILE]` | Write waiting messages (with their 3.1.0 transaction ids) and queued forwards as JSON Lines. Opens the store read only. |
| `epicmail import FILE` | Load messages and forwards from JSON Lines; ones already present are skipped, so it can be repeated. |

All take `--config FILE` (default `/etc/epicmail/epicmail.toml`).

## Configuration

One TOML file. Every setting except `server.domain` has a default; unknown keys and invalid
values are refused at load, and `check-config` checks a file before a restart. Every setting,
with its default and a comment, is in
[packaging/epicmail.example.toml](packaging/epicmail.example.toml); `src/config.rs` is the
reference.

| Section | Holds |
|---|---|
| `[server]` | Listener, identity (`domain`, `port`, `aliases`), trusted proxies, metrics listener, drain time, display name |
| `[store]` | Database path, retention, live-size cap, group commit size, reader connections, vacuum hour |
| `[protocol]` | Challenge interval, `GetVersion` answer, cancel and mux/1 switches, ping and idle timeouts, watchdog |
| `[limits]` | Sizes, rates per network prefix and per sender, socket caps, mailbox caps, mux/1 and `/v1` budgets |
| `[federation]` | Forwarding to other relays: on/off, allow and deny lists, explicit peer URLs, timeouts, parallel lanes |
| `[http_api]` | The `/v1` API: on/off, batch sizes, long-poll time and caps, challenge window, lease |
| `[log]` | `text` or `json`, and the log filter (`RUST_LOG` overrides it) |

Per-IP limits apply per network prefix (`/24` for IPv4, `/48` for IPv6). Addresses many users
share, such as a Tor onion service's local address, go in `limits.shared_sources` for a larger
budget. `server.trusted_proxies` must list the reverse proxy, or every client is counted as
the proxy.

## Protocols

### Epicbox websocket (2.0.0, 3.0.0, 3.1.0)

Wallets connect with a websocket to any path. The relay sends a `Challenge`, and then a new one
every `protocol.challenge_interval_s` (60 s). A wallet proves a mailbox by signing the current
challenge in `Subscribe`, posts with `PostSlate`, receives `Slate` frames and acknowledges each
with `Made`. Version differences:

| | 2.0.0 | 3.0.0 | 3.1.0 |
|---|---|---|---|
| `Made` signed over | the current challenge | the message id | the message id |
| `Slate` carries | `epicboxmsgid`, `ver` | `epicboxmsgid`, `ver` | also `epicboxtxid` when the slate has one |
| Cancel | no | no | `epicboxtxid` and `epicboxtxidsig` on `PostSlate`, `CancelTx`, `TransactionCancelled` |

Differences from the original relay that a wallet can observe, all within what wallets accept:

- Every challenge is random, the first one included.
- A `Subscribe` signed over the previous challenge is still accepted until the next successful
  one, because the interval challenge can cross a `Subscribe` in flight.
- A delivered slate is leased for 60 s rather than holding the mailbox until `Made`. After three
  `Subscribe`s without a `Made` for it, the slate goes behind the other waiting ones.
- A socket that leaves three interval challenges unanswered while mail waits for it is closed
  with 1001 so the wallet reconnects (the watchdog).
- A malformed frame closes only its own socket (code 3000, as before); other sockets are not
  affected.
- Only the newest classic socket of a mailbox receives pushes; older ones stay open, up to
  `limits.sockets_per_address`, and collect on their next `Subscribe`.

### mux/1

Opt-in: a client sends `ClientDetails` with `"ext":["mux/1"]` before its first `Subscribe`, then
carries many mailboxes on one socket, each proven once with `Attach`. It gets several messages
in flight, signature-free `Ack`, `Hold` for a message it cannot handle yet, `Waiting` counts, and
a single-use resume token for reconnecting without signing again. Specification:
[docs/mux-1.md](docs/mux-1.md). The protocol is frozen at version 1; a change needs a new name.

### HTTPS pull API (`/v1`, `epicbox-https/0.1`)

For clients that cannot hold a websocket. The client makes its own challenge,
`ebh-<unix seconds>-<random lowercase hex>`, and signs it with the mailbox key. A challenge is
accepted once per key and only inside `http_api.challenge_window_s`.

| Endpoint | Body | Answer |
|---|---|---|
| `GET /v1/info` | | Protocol name, identity, challenge format, limits |
| `POST /v1/post` | A `PostSlate` object without `type` | `{"ok":true,"id":...}`; 400, 409 (cancelled), 429 (rate limit with `Retry-After`, or mailbox full) or 503 |
| `POST /v1/pull` | `{"mailboxes":[{"address","challenge","signature"}],"limit":20,"wait":0..25}` | Waiting messages per mailbox; with `wait`, a long poll that returns when mail arrives |
| `POST /v1/made` | `{"address","acks":[{"id","signature"}]}`, each signature over the id | `{"removed":n,"refused":n}` |

Pulled messages are leased for `http_api.lease_s` seconds and offered again if not
acknowledged. Long polls are capped per prefix and in total; over the cap a pull gets 429 with
`Retry-After`.

### Other HTTP endpoints

| Path | Use |
|---|---|
| `/health` | Liveness: the process answers. |
| `/ready` | Readiness: the store is writable (written at most every 5 s). 503 while draining. |
| `/metrics` | Prometheus text, names start with `epicbox_`. Only to loopback requests without `X-Forwarded-For`, or on `server.metrics_listen`. |
| `/status.json` | Public totals: sockets, waiting messages, uptime. No per-address data. |
| `/.well-known/epicbox.json` | Software, version, identity, protocol versions, federation, features and their limits. |

## Transaction cancel (3.1.0)

A 3.1.0 `PostSlate` carries `epicboxtxid`, a 32-character transaction id, and
`epicboxtxidsig`, the sender's signature over it. The relay links the transaction to its
participants (the sender's and the receiver's keys) and, when the sender is on another relay,
to that relay.

The cancel follows the reference 3.1.0 relay, so cancels pass between it and epicmail in both
directions.

- **Who may cancel.** `CancelTx {address, epicboxtxid, signature}` from a participant, on any
  socket: a wallet's own, or another relay's that never subscribed. The signature is over the
  bare txid, as wallets and the reference relay sign it, or over `epicbox-cancel/1:<txid>`.
- **What the bare signature proves.** It is the same signature the `PostSlate` carried as
  `epicboxtxidsig`, so anyone who saw the slate (its recipient, a relay on the path) can cancel
  the transaction. A signature over `epicbox-cancel/1:<txid>` is produced only for a cancel;
  epicmail accepts it, and wallets that want cancels only the sender can make should sign that
  form. It reaches only relays that accept it too.
- **What happens.** Every waiting state of the transaction is deleted, a cancel record is kept
  for the retention period, and the requester gets `TransactionCancelled`. The receiver's 3.1.0
  sockets get `TransactionCancelled` pushed; a receiver offline at the time gets it on its next
  `Subscribe`, and the following successful `Subscribe` acknowledges it. A later `PostSlate`
  with the same txid gets `TransactionCancelled` instead of `Ok`.
- **Non-participants** get a plain `Ok` and change nothing, so the answer does not reveal
  whether the transaction exists.
- **Across relays.** A cancel is forwarded to every other relay that holds states of the
  transaction, under the same federation policy as slates, with a `cancelrequestid` (made when
  the request has none). A request id seen in the last 10 minutes is confirmed with
  `TransactionCancelled` and not processed or forwarded again, which ends relay loops.
  `protocol.forward_bare_cancel = false` forwards only cancels signed over
  `epicbox-cancel/1:<txid>`.
- **All or nothing.** The cancel record, the deletion of waiting states and the queued forward
  to each other relay are stored in one transaction. If storing fails, the requester gets an
  error, nothing is kept, and the request (or the same request from a relay) can be sent again.
  Each relay is queued once per transaction: a retry queues only relays not queued before, and
  a cancel that comes back from a relay is not sent to it again.
- **`Made` on a 3.1.0 slate** also removes the other waiting states of that transaction in the
  same mailbox.

`protocol.cancel = false` turns all of this off; the relay then behaves as a 3.0.0 relay.

## Federation

A slate whose destination is another relay's domain is queued and forwarded over `wss://`. The
relay resolves the peer's name itself and refuses private, loopback, link-local and other
special addresses (unless `federation.allow_private` is set for a test rig), connects to the
checked address and verifies the certificate against the peer's domain, so a crafted
destination cannot reach internal services. `federation.allow` restricts forwarding to listed
relays, `federation.deny` excludes some, `federation.peers` maps a name to an explicit URL, and
`federation.enabled = false` refuses posts for other relays.

A failed delivery is retried with exponential backoff from 5 s to 1 hour, per peer: an
unreachable peer waits as a whole. A peer that answers `Error` three times for one frame has
refused it and the forward is dropped. Forwards expire with the retention period. Incoming
forwards are ordinary `PostSlate`s from another relay's connection and pass the same checks as
a wallet's.

## Data and retention

| Data | Kept until |
|---|---|
| Waiting slate | Acknowledged (`Made`, mux/1 `Ack`, `/v1/made`), or `store.retention_days` after posting (default and minimum 7) |
| Queued forward | Delivered, refused three times, or the retention period |
| Cancel record and transaction links (participant keys, peer relay) | The retention period |
| Used `/v1` challenge | The end of its challenge window |
| mux/1 resume token | Used, replaced, or 24 hours; memory only, gone on restart |
| Rate-limit state | Memory only |

The store is one SQLite file. It holds what a relay needs to deliver: the slate (ciphertext
encrypted by the wallets for the receiver), the sender and recipient addresses, signatures,
timestamps and delivery counts. It holds no client IP addresses. Deleted slates are overwritten
in place where SQLite can do so without extra I/O (`secure_delete=FAST`), and free pages are
returned to the file system by a daily vacuum. `store.max_bytes` (2 GiB by default) caps the
live data; above it posts are refused while collecting continues.

## Logging and metrics

Logs go to stderr (journald under systemd). Levels: `error` when the relay cannot do its job,
`warn` when something outside it misbehaves (a peer relay, a full store), `info` for lifecycle,
expiry sweeps and limit refusals, `debug` for one line per socket, post, subscribe, attach and
cancel.

- Keys, addresses and txids appear only shortened to their first and last six characters,
  clients only by network prefix (on limit refusals, and at debug on socket open), peer relays
  by host name. Slates, signatures, challenges, message ids, resume tokens and client IPs are
  never logged; `tests/log_privacy.rs` checks this at debug level.
- Lines a client can make repeat are sampled to 10 a minute per call site, each with a
  `suppressed` count, so an attack or a failing disk cannot flood the log.
- Rotation and retention are left to journald or the container log driver; the settings are in
  [docs/operating.md](docs/operating.md#8-logging).

Metrics are Prometheus counters and gauges named `epicbox_*`; labels carry outcomes and limit
names only. The ones to watch first are listed in
[docs/operating.md](docs/operating.md#4-reading-the-health-endpoints).

## Security model

- **What the relay sees.** Slates are encrypted by the wallets; the relay stores and forwards
  ciphertext. It does see metadata: sender and receiver addresses, sizes, timing, and client IP
  addresses on connections. A mux/1 socket also shows which mailboxes belong together. Treat the
  database, and the reverse proxy's access log, as private.
- **What it trusts.** Reading or acknowledging a mailbox needs a signature by its key: over a
  relay challenge (`Subscribe`, mux/1 `Attach`), over a single-use client challenge (`/v1`), or
  over the message id (`Made`). A mux/1 socket that proved a mailbox may `Ack` without
  signatures, and its resume token is a bearer secret (24 hours, single use, stored only as a
  hash). Posting needs the sender's signature over the slate; the relay cannot forge or alter a
  slate, and a wallet checks the slate itself.
- **Random challenges.** The original protocol has the relay send one fixed challenge on every
  new socket, so a first `Subscribe` signature never expires and can be replayed by anyone who
  has seen it. epicmail sends a fresh random challenge on every socket and every round and
  accepts no signature over the fixed value. A replayed signature and an older wallet's
  signature are byte for byte the same, so the relay cannot accept one and refuse the other;
  that is why wallets before 3.5.2 cannot receive here.
- **Federation** cannot be pointed at internal addresses (see [Federation](#federation)).
- **Trusted proxies.** `X-Forwarded-For` is read only from addresses in
  `server.trusted_proxies`, from the right. List only your own proxy, and make it replace the
  header (the examples do).
- **Keep private:** `/metrics` (the proxy examples return 404 for it) and the test switch
  `test.stall_endpoint`, which must stay off on a public relay.
- **Sandbox.** The systemd unit runs with a dynamic user, no capabilities, a read-only system
  and a system call filter; the container runs as an unprivileged user on an empty base.
- **Dependencies.** `deny.toml` fails the dependency check on any RustSec advisory,
  non-permissive licence, unknown source or OpenSSL; TLS is rustls with ring. Signatures use
  the `secp256k1` crate, the Rust binding of Bitcoin Core's libsecp256k1.
- **Reporting.** Report vulnerabilities privately through the repository's private
  vulnerability reporting, not in a public issue.

## Known limits

- **One node.** The store is SQLite with one writer. One process serves everything; there is
  no clustering or shared store. A standby restored from backup covers most availability needs;
  [docs/operating.md](docs/operating.md#7-when-to-switch-to-postgres) says when that stops
  being enough.
- **No TLS of its own.** It expects a reverse proxy in front.
- **Wallets before 3.5.2 cannot receive** (see above).
- **Per-prefix limits are coarse.** Many users behind one carrier NAT or Tor exit share a budget
  unless their source is listed in `limits.shared_sources`; one user with many prefixes gets
  many budgets. `store.max_bytes` bounds the total in any case.
- **Metadata.** Addresses and timing are visible to the operator, as on any Epicbox relay.
- **Cancel authority.** A cancel signed over the bare txid, the form wallets use today, can be
  sent by anyone who saw the slate (see [Transaction cancel](#transaction-cancel-310)). This is
  the protocol's, kept for interoperability.
- **Export** carries waiting slates and forwards, not cancel records, so a cancel made before a
  migration is not known to the new store.
- **Extensions are epicmail's own.** mux/1 and `/v1` are not served by other relays; clients that
  use them should fall back to the classic protocol.

## Questions

**I maintain a wallet. Do I need to change anything?** No. A wallet that speaks Epicbox 2.0.0,
3.0.0 or 3.1.0 and signs the random first challenge works unchanged. If your wallet still signs
the fixed constant on a new socket, it needs the change that 3.5.2 made.

**Which version should my wallet announce?** `3.1.0` if it implements cancel, otherwise
`3.0.0`. A `3.1.0` `Subscribe` makes the relay push `TransactionCancelled`; a wallet that does
not understand that frame should not announce 3.1.0.

**What does a wallet see when the relay is overloaded?** An `Error` frame with
`Rate limit exceeded; retry in N s.` for rate limits, `Recipient mailbox is full; try again
later.` for a full mailbox, and `Relay storage is full; try again later.` when the store is at
its cap. Nothing is half-stored.

**Can a slate be delivered twice?** A slate is deleted only on `Made`, so a wallet that does not
send `Made` (or whose `Made` is lost) receives it again after the lease. Wallets already handle
a repeated slate. The same slate posted twice is stored once.

**How do I run a private relay for one service?** Set `federation.enabled = false` (or an
`allow` list), put the service's address in `limits.shared_sources` if it holds many mailboxes,
and consider mux/1 or `/v1` for it.

**How do I monitor it?** Probe `/ready`, scrape `/metrics`, and alert on `error` log lines.
[docs/operating.md](docs/operating.md) lists the metrics to watch.

**How do I upgrade or roll back?** Back up, `check-config` with the new binary, replace,
restart. The database carries a schema version and a binary refuses a version it does not know.
Details in [docs/operating.md](docs/operating.md#9-upgrade-and-roll-back).

**How do I move from another relay?** Export its queue with `tools/export-node-pg.py` (Node and
Python Postgres-backed relays) and `epicmail import` the file into the new store. Change DNS
when the import is done; wallets reconnect on their own.

**What is logged about my users?** See [Logging and metrics](#logging-and-metrics): shortened
keys at debug level, network prefixes on limit refusals, never full addresses or IPs.

## Contributing

Issues and pull requests are welcome. Before sending a change:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

`cargo test` runs the unit tests, `tests/loopback.rs` (relays on loopback ports driven over
websocket and HTTP, including federation between two relays), `tests/log_privacy.rs` and the
signature differential test against recorded cases
([tools/sigdiff/README.md](tools/sigdiff/README.md)). `tools/compat-classic.sh` runs real
classic wallets against two local relays; its header lists what it needs.

- Keep wire compatibility: a classic wallet must never receive a frame it cannot parse, and
  error texts match the original relay. mux/1 is frozen.
- Add a test with each fix, preferably one that fails without it.
- Keep commits small, with a subject of the form `Area: what changed` and the reason in the
  body.
- Log through the helpers in `src/logging.rs`: shorten keys with `short`, sample anything a
  client can repeat with `sampled!`, and never log addresses, slates, signatures, tokens or IPs.
  Never put them in metric labels.

### Source map

| Path | What it does |
|---|---|
| `src/main.rs` | CLI, startup, housekeeping, shutdown |
| `src/config.rs` | Configuration file, defaults and checks |
| `src/http/` | HTTP routes and the websocket upgrade (`mod.rs`), the `/v1` API (`v1.rs`) |
| `src/relay/` | Shared state, posting, cancel, resume tokens, the socket registry, long-poll waiters and the websocket sessions |
| `src/store/` | The `Store` trait and the SQLite store |
| `src/forward.rs` | Forwarding to other relays |
| `src/limits.rs` | Rate limits and socket counts |
| `src/address.rs`, `src/sig.rs` | Epicbox addresses and signatures |
| `src/logging.rs`, `src/metrics.rs` | Log setup and helpers, Prometheus metric descriptions |
| `src/migrate.rs` | JSON Lines import and export |
| `src/clock.rs`, `src/ids.rs` | Wall-clock milliseconds, random ids and id checks |
| `examples/` | Load generator, day simulation, live check of a deployed relay, route check between relays |
| `src/bin/sigdiff-gen.rs`, `tests/sigdiff.rs` | Signature differential test |
| `packaging/` | systemd unit, nginx and Caddy examples, example config |
| `tools/` | Static build, classic wallet compatibility run, export from Postgres-backed relays |
| `deny.toml` | Dependency policy for `cargo deny` |

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
