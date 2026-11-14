# Architecture

epicmail is one process: a tokio runtime serving websockets and HTTP on one listener, a SQLite
store with a single writer thread, a forward manager for other relays, and a housekeeping task.
All of it shares one `Relay` value (`src/relay/mod.rs`).

## Modules

| Module | Job |
|---|---|
| `main.rs` | CLI (`serve`, `check-config`, `import`, `export`, `selftest`), startup, housekeeping, SIGTERM drain |
| `config.rs` | The TOML file, its defaults and its checks |
| `http/mod.rs` | The axum router: websocket upgrade, `/health`, `/ready`, `/metrics`, `/status.json`, `/.well-known/epicbox.json` |
| `http/v1.rs` | The `/v1` HTTPS API and its challenge auth |
| `relay/mod.rs` | Shared state and the types every entry point uses |
| `relay/post.rs` | `post_slate`: the rules for posting a slate, from any entry point |
| `relay/cancel.rs` | `cancel_tx`: the 3.1.0 cancel |
| `relay/tokens.rs` | mux/1 resume tokens |
| `relay/registry.rs` | Which socket holds which mailbox, and waking it |
| `relay/session/` | One task per websocket: the shared event loop, classic frames (`classic.rs`) and mux/1 frames (`mux.rs`) |
| `store/mod.rs` | The `Store` trait and its record types |
| `store/sqlite.rs` | The SQLite implementation |
| `forward.rs` | Delivery to other relays |
| `limits.rs` | Rate limits and socket counts per IP prefix |
| `address.rs`, `sig.rs` | Address grammar and signature checks, both matching the stock relay |
| `metrics.rs` | Prometheus exporter and metric descriptions |
| `migrate.rs` | JSON Lines import and export |
| `clock.rs`, `ids.rs` | Wall-clock milliseconds, random ids and id checks |

## Message flow

1. **Post.** A wallet sends `PostSlate` on a classic socket, `PostSlate` on a mux/1 socket, or
   `POST /v1/post`. All three call `Relay::post_slate`. It applies the per-IP rate and byte
   limits, checks sizes, parses both addresses, verifies the slate signature (and the 3.1.0 txid
   signature), applies the per-address limit, and reads the destination from inside the signed
   slate.
2. **Store.** If the destination is this relay (`server.domain`, `server.port` or an alias),
   the message goes to `Store::put_message`. The store enforces `queue_cap` and
   `per_sender_cap`, keeps one copy of a slate posted twice, and links the message to its 3.1.0
   transaction. The call returns after the commit; only then does the wallet get `Ok`.
3. **Wake.** After the commit the relay wakes the mailbox's holder through the registry. The
   registry pushes to one socket per mailbox: the mux/1
   holder if there is one, else the newest classic subscriber. `/v1` long polls waiting on that
   mailbox are woken through `relay/waiters.rs`, which wakes only the pulls for that mailbox;
   waiting pulls are capped per IP prefix and in total (`http_api.max_waiting_per_ip`,
   `http_api.max_waiting`).
4. **Deliver.** The woken session claims the next message from the store. A claim is a lease
   (`OFFER_LEASE_MS`, 60 s on classic sockets; `http_api.lease_s` on `/v1`), so a socket that
   dies does not block the mailbox. Classic sockets have one message in flight; mux/1 sockets
   up to `limits.mux_inflight`.
5. **Acknowledge.** `Made` (classic), `Ack` (mux/1) or `POST /v1/made` deletes the message.
   Wallets older than 2.0.0 send no `Made`, so their messages are deleted on delivery. A message
   that is never collected expires after `store.retention_days`.

On a classic socket, each Subscribe that arrives while a message is in flight without `Made`
counts. On the Subscribe after three such, the message stays in the store, but its lease is
released and the store orders it after the other waiting messages, so one slate a wallet cannot
handle does not block the rest of the mailbox. mux/1 and `/v1` have no such count.

## Federation

If the destination is another relay, `post_slate` checks `federation.enabled`, the allow and
deny lists, and the domain form (`Relay::forward_refusal`; CancelTx forwards and every delivery
round apply the same checks), then stores the `PostSlate` frame as a forward row with
`Store::put_forward` and answers `Ok` after that commit. The forward manager (`forward.rs`) is
woken at once and also wakes every 5 s. It runs one lane per peer `domain:port`, at most
`federation.max_lanes` at a time. A lane opens a fresh websocket per forward, waits for the
peer's `Challenge`, sends the frame and reads until `Ok`, `TransactionCancelled` or `Error`.

Peer names are resolved by the relay, and each address is checked: private, loopback,
link-local and other special ranges are refused unless `federation.allow_private` is set. The
TCP connection goes to the checked address and TLS checks the certificate against the peer's
domain. A failed attempt is retried with exponential backoff from 5 s up to 1 hour. A peer that
answers `Error` three times for one frame has refused it, and the row is dropped. Rows expire with
the same retention as messages.

A 3.1.0 `CancelTx` whose other party is on another relay is forwarded the same way.

## Group commit

`store/sqlite.rs` has one writer thread that owns the only write connection. Callers send their
write over a channel and wait for the answer. The writer takes every write that is waiting, up to
`store.group_commit_max`, runs each in its own savepoint inside one transaction, commits once,
and then answers all callers. A write that fails rolls back its savepoint only. Under load this
turns many fsyncs into one, which is where the throughput in `docs/loadtest.md` comes from.

Readers use a pool of `store.readers` read-only connections; WAL mode lets them read while the
writer commits. `epicbox_store_commit_seconds` and `epicbox_store_commit_batch` show the
writer's latency and batch size.

## Limits

`limits.rs` groups clients by IP prefix (`ipv4_prefix`, `ipv6_prefix`). The client IP comes from
`X-Forwarded-For` only when the peer is in `server.trusted_proxies`. Sources in
`shared_sources` get every per-prefix budget multiplied by `shared_multiplier`.

- Token buckets per prefix: posts, posted bytes, failed signatures, mux/1 Attach and Resume
  frames, and `/v1` work (one unit per pulled mailbox or acked id).
- Token buckets per sender address: posts.
- Counters: sockets per prefix, mux/1 sockets per prefix, sockets in total. A socket holds a
  `SocketPermit` that gives its slot back when dropped.
- Per socket, in the session: frames per minute, frame and string size, mux/1 mailboxes,
  attach frames and messages in flight. A write that the client does not take within
  `protocol.idle_timeout_s` ends the session.
- Memory: mux/1 resume tokens outlive their sockets, so the mailboxes they hold are capped
  (`mux_token_mailboxes`); the oldest tokens go first.
- In the store: `queue_cap` and `per_sender_cap`.

A refusal increments `epicbox_limit_refusals_total{limit=...}`. Rate refusals tell the client
when to retry: in the error text on websockets, in `Retry-After` on `/v1`.

## Background tasks

`main.rs` starts the forward manager and one housekeeping loop:

- every 15 s: the gauges (waiting messages and mailboxes, oldest message and forward, listening
  mailboxes, mux/1 holders and tokens, database size, store health);
- every minute: prune idle rate-limit buckets and expired mux/1 resume tokens;
- at start and every 5 minutes: delete expired messages, forwards, cancel records, used `/v1`
  challenges and transaction links;
- once a day at `store.vacuum_hour_utc`: incremental vacuum.

On SIGTERM the relay refuses new sockets, `/ready` reports not ready, mux/1 sockets get
`Detached` frames with reason `shutdown`, sockets are closed with code 1001, and the process waits
up to `server.drain_seconds` for them to finish.

## Metrics

`metrics.rs` installs the Prometheus exporter. All names start with `epicbox_`. Labels carry
outcomes and limit names only, never addresses, keys, IPs or payloads. See `docs/operating.md`
for which metrics to watch first.

## Ideas not built

### Wake hints for servers that cannot hold a connection

A server that can hold one outbound connection is served by mux/1 or the `/v1` long poll, with no
new state at the relay. A webhook would help receivers that only take inbound HTTP. If it is
built, the safe shape is narrow and off by default:

- The operator lists allowed callback hosts in the config file. Only HTTPS on port 443 to those
  hosts. This avoids most server-side request forgery: no other host is ever called.
- The mailbox owner registers a hook with a signature over the relay id, URL, expiry and nonce,
  and the URL owner proves it consents by returning a verification token through the relay.
- The callback carries only an opaque subscription id and says "mail is waiting". It is signed
  with the Standard Webhooks scheme (HMAC-SHA256 over id, timestamp and body). The receiver then
  pulls through `/v1` or mux/1.
- Hints are level-triggered and coalesced: at most one in flight per subscription, a minimum
  interval, retries only while mail is waiting.
- The HTTP client resolves names itself, refuses non-global addresses (including IPv4-mapped and
  NAT64 forms), connects to the checked address, follows no redirects and ignores proxy
  variables.
- Logs hold no mailbox, URL or host; metrics are totals.

The core already has what this needs: `post_slate` wakes listeners right after each commit
(`relay/post.rs`), which is where a notifier would be called, and the store can answer which
mailboxes have waiting mail. Phones need a different path (Web Push), which
would share the outbound client and the address checks.
