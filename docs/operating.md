# Operating the relay

One binary, one TOML file, one SQLite database.

```
epicmail serve        --config epicmail.toml
epicmail check-config --config epicmail.toml
epicmail import       --config epicmail.toml <file>
epicmail export       --config epicmail.toml [--out file]
epicmail selftest     --config epicmail.toml
```

`--config` (`-c`) defaults to `/etc/epicmail/epicmail.toml`. `selftest` signs and verifies a test message, checks that the store is writable, then exits.

## 1. Install

### One-line install

```
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh -s -- --domain relay.example.org
```

To upgrade, run it without `--domain`:

```
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh
```

`tools/get.sh` downloads a release's static binary and its `SHA256SUMS`, and refuses them unless
the binary matches the checksum and the signature on `SHA256SUMS` verifies against the release
key pinned in the script. `minisign` must be installed; the check cannot be skipped. It then
fetches `install.sh`, `epicmail.service` and `epicmail.example.toml` from the same release,
checks each against the signed `SHA256SUMS`, and only then runs that install script (below) with the
binary and the packaging files. A release whose `SHA256SUMS` lists none of them (before 0.1.7)
is refused; install it from a checkout instead. Unless `--no-tls`,
it then installs Caddy from Caddy's own apt or dnf repository and writes `/etc/caddy/Caddyfile`
with a site for the domain that proxies to the relay (websocket upgrade, one-hour timeouts,
`/metrics` answered with 404). It never changes a web server it did not install: with nginx,
Apache, another Caddy setup or anything on port 80 or 443 already there, it prints the site to
add instead. Caddy has no per-address rate limits; for those, use nginx with
`packaging/nginx.example.conf`.

### Install script

On Linux with systemd, `tools/install.sh` does the binary and systemd steps below in one go. Run
it from a checkout as your own user; it builds with cargo and uses sudo only to install.

```
tools/install.sh --domain relay.example.org   # first install: build, configure, start
tools/install.sh                              # upgrade: back up, build, check, replace, restart
tools/install.sh --uninstall                  # remove service and binary; config and data stay
```

A first install writes `/etc/epicmail/epicmail.toml` from the example with `server.domain` and
`store.path = "/var/lib/epicmail/epicmail.db"` set, installs the binary as
`/usr/local/bin/epicmail` and the unit as `epicmail.service`, starts it and waits for `/ready`.
An existing config is never changed. An upgrade first backs up the store with `sqlite3` into
`/var/backups/epicmail/`, then runs `check-config` with the new binary before it replaces
anything. `--name` installs a second instance with its own unit, config and data directories (add
`--prefix` to keep its binary apart too), `--bin` installs a binary built elsewhere, and `--help` lists the rest.

### Binary

```
tools/build-static.sh        # static x86_64 musl binary
install -m 0755 target/x86_64-unknown-linux-musl/release/epicmail /usr/local/bin/
install -d /etc/epicmail
cp packaging/epicmail.example.toml /etc/epicmail/epicmail.toml   # edit server.domain, store.path
epicmail check-config --config /etc/epicmail/epicmail.toml
```

### Docker

```
docker build -t epicmail .
docker run -d --name relay --restart on-failure \
  -p 127.0.0.1:3423:3423 \
  -v relay-data:/data \
  -v relay-logs:/var/log/epicmail \
  -v /etc/epicmail/epicmail.toml:/etc/epicmail/epicmail.toml:ro \
  epicmail
```

In the container config set `server.listen = "0.0.0.0:3423"` and `store.path = "/data/epicmail.db"`. Behind a reverse proxy on the host, the container sees connections from the Docker bridge gateway (often `172.17.0.1`), not `127.0.0.1`: put that address, or the bridge network such as `172.16.0.0/12`, in `server.trusted_proxies`. Otherwise the relay ignores `X-Forwarded-For` and every client shares one per-prefix budget, 256 sockets for the whole relay. The image runs as uid 65532 on a `scratch` base and has no shell, so there is no HEALTHCHECK. Check from outside instead: `curl -fsS http://127.0.0.1:3423/ready` from the host or the reverse proxy, or a Compose/orchestrator probe on `/ready`. Stop with `docker stop -t 30`: the default 10 s equals `drain_seconds`.

### systemd

```
install -m 0644 packaging/epicmail.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now epicmail
```

The unit uses `DynamicUser` and `StateDirectory=epicmail`, so set `store.path = "/var/lib/epicmail/epicmail.db"`. `LimitNOFILE=262144` covers `max_sockets = 150000`. `TimeoutStopSec=30` must stay above `server.drain_seconds`.

### Reverse proxy

Terminate TLS in front of the relay: `packaging/Caddyfile.example` or `packaging/nginx.example.conf`. Both:

- pass the websocket upgrade;
- keep a read timeout of 3600 s (wallets hold sockets that long; never shorten it);
- set `X-Forwarded-For` to the client address;
- answer 404 for `/metrics`.

List the proxy in `server.trusted_proxies`. Without it the relay sees every client as the proxy and applies the per-IP limits to all of them at once. Do not list peer relays or clients there.

## 2. Configuration

All settings, with defaults and one-line comments, are in `packaging/epicmail.example.toml`. The code is the reference: `src/config.rs`. Unknown keys are rejected. Run `check-config` after every edit. Only `server.domain` is required.

## 3. Limits

Per-IP limits group clients by prefix (`ipv4_prefix` 24, `ipv6_prefix` 48). Sources in `shared_sources` get their per-prefix limits multiplied by `shared_multiplier`.

| Field | Default | Protects against |
|---|---|---|
| `max_frame_bytes` | 1 MiB | Memory use from one huge frame |
| `max_str_bytes` | 128 KiB | Oversized slate or string fields |
| `posts_per_min_per_address` | 60 | One sender flooding |
| `posts_burst_per_address` | 120 | Same, burst size |
| `posts_per_min_per_ip` | 240 | One client flooding many destinations |
| `posts_burst_per_ip` | 480 | Same, burst size |
| `bytes_per_min_per_ip` | 16 MiB | Disk fill by few large posts; large frames of other kinds (each websocket frame that is not a PostSlate counts its size here, and a socket over the budget is closed with 1008) |
| `frames_per_min_per_socket` | 1200 | One chatty socket using CPU |
| `queue_cap` | 2000 | One mailbox growing without bound |
| `per_sender_cap` | 200 | One sender filling a mailbox |
| `sockets_per_ip` | 256 | One prefix using all sockets |
| `sockets_per_address` | 4 | Many sockets on one address |
| `failed_sigs_per_min_per_ip` | 120 | Signature guessing, CPU burn on verification. A socket is closed with 4003 after 8 failed signatures; a socket's first signed frame and re-proofs of a key it already proved are not refused by the prefix limits, so one client cannot lock out the others in its prefix |
| `sig_checks_per_min_per_ip` | 1200 | CPU burn by valid signatures: Subscribe, Made and CancelTx each cost one check, a mux/1 Attach one per mailbox. Without it a few sockets can keep a core busy with valid Subscribes. A service that attaches many mailboxes from one address belongs in `shared_sources` |
| `mux_mailboxes_per_socket` | 256 | One mux/1 socket attaching everything |
| `mux_attach_per_frame` | 64 | Large attach frames |
| `mux_inflight` | 32 | Mail pushed on one mux/1 socket and not yet acked or held |
| `mux_attach_frames_per_min` | 30 | Attach/resume churn; a prefix gets 8 times this across its sockets |
| `ipv4_prefix` / `ipv6_prefix` | 24 / 48 | Sets how clients are grouped for per-IP limits |
| `max_sockets` | 150000 | Total file descriptors and memory |
| `shared_sources` | empty | Tor exits and onion clients being limited as one client. Behind the shipped nginx onion setup, onion clients arrive as `fc00:dead:beef:4dad::<circuit>`: use `["fc00:dead:beef:4dad::/64"]`. Use `["127.0.0.1/32"]` only when tor connects straight to the relay with nothing in between |
| `shared_multiplier` | 16 | Factor applied for `shared_sources` |
| `mux_sockets_per_ip` | 64 | One prefix holding many mux/1 sockets |
| `http_per_min_per_ip` | 1200 | `/v1` floods: each pulled mailbox costs a signature check and a database write |
| `mux_token_mailboxes` | 1000000 | Memory held by mux/1 resume tokens of closed sockets (oldest dropped first) |

`queue_cap` caps one mailbox, but anyone can make new addresses, so per-mailbox caps do not bound the database. What does: `bytes_per_min_per_ip` per prefix (16 MiB a minute is about 160 GB over 7 days of retention for one /24) and, for the whole relay, `store.max_bytes` (default 2 GiB of live data). Over `store.max_bytes` every post is refused with "Relay storage is full; try again later." (`/v1/post`: 429) until wallets collect mail or it expires; subscribing, collecting and acking keep working. `/v1/pull` writes a short-lived replay row per mailbox, so pulls are refused (503) once live data reaches 125% of the cap, which stops pulls alone from filling the disk. Set it well below the free disk space, and watch `epicbox_store_used_bytes` and `epicbox_limit_refusals_total{limit="store_bytes"}`.

The relay's limits group clients by prefix and act once a request has reached it. In front of
it, `packaging/nginx.example.conf` adds per-address limits on new websocket connections, open
connections, the public GET routes (which the relay does not limit) and `/v1` requests. They
matter most on a small host, where a flood of public GETs would otherwise reach the relay. A
flood of new TLS connections still costs nginx the handshakes; only a firewall rate limit on
new connections avoids that.

## 4. Reading the health endpoints

- `/health`: the process is up and answering. Use it for liveness. It does not look at the store.
- `/ready`: the store is writable. Use it for load balancer and orchestrator checks. It writes to the store at most once every 5 s and answers probes in between from that result. A failure means the disk is full or read-only, or the DB file is damaged. During a SIGTERM drain it may also report not ready.
- `/metrics`: Prometheus text, metric names start with `epicbox_`. Look first at open sockets (against `max_sockets`), posts accepted and rejected (`epicbox_limit_refusals_total` by limit name shows which limit fires), store commit latency and batch size (`epicbox_store_commit_seconds`, `epicbox_store_commit_batch`), live data against `store.max_bytes` (`epicbox_store_used_bytes`), federation deliveries and failures (`epicbox_forwards_total`, with `result="unanswered"` for cancels a peer never answered), forwards given up on (`epicbox_forwards_dropped_total{peer,reason}`, reason `refused`, `policy`, `loop` or `unanswered`) and forwards that ran out their retention (`epicbox_forwards_expired_total`). Posts the federation allow/deny list refused show as `epicbox_posts_total{result="policy"}`. When `server.metrics_listen` is unset, it is served on `server.listen` to loopback peers whose request carries no `X-Forwarded-For`, so requests that came through the reverse proxy get 404. Set `server.metrics_listen` to serve it on a separate address instead, for example a private one a scraper on another host can reach.
- `/status.json`: a small JSON summary for people and status pages: name, sockets, queue totals, uptime. It is public; it holds no per-address data. Queue totals are refreshed every 15 s, not per request.
- `/.well-known/epicbox.json`: the info document wallets and peers read: software (no exact version), `server.name`, identity (`domain:port`), protocol versions, whether federation is on, the mux/1 and HTTPS features with the limits a client needs (the per-IP abuse limits are not published), `txcancel/1` when mux/1 and the 3.1.0 cancel are both on, and `epicbox-cancel/1` (the text its cancels may be signed over) when the 3.1.0 cancel is on.
- `/` in a browser: a page for people who open the relay's address. It says what the relay is, shows the domain and port to enter in a wallet, and runs three checks from the visitor's browser every 30 s: `/health`, `/ready` and a websocket that must receive its first `Challenge`. It shows nothing beyond those routes and the info document, loads nothing from other hosts, and is sent only for `GET /` with `Accept: text/html`; every other plain GET still gets the one-line text. `server.landing_page = false` turns it off.

### Payment metrics

These are counts only. No label or log field holds an address, a txid, an IP or a mailbox, and there is no lookup by any of them.

- `epicbox_posts_total{result,txid}`: PostSlate results; `txid="yes"` when the post carried an `epicboxtxid`.
- `epicbox_post_size_total{size,txid}`: accepted posts by size of the slate body (`le_2560`, `le_5120`, `le_6144`, `le_10240`, `over_10240` bytes).
- `epicbox_roundtrip_seconds`: histogram of the time from the first slate stored under a txid to the first slate from the other party under the same txid (buckets 5 s to 3 days).
- `epicbox_roundtrip_unanswered`: transactions whose first slate is older than `store.unanswered_hours` (default 24, 1 to `retention_days` times 24), that have no slate from the other party under that txid, and are not cancelled. It is recomputed every 15 s. A payment that never completes shows here until it is cancelled or its rows expire. Rows older than `store.retention_days` are gone, so the gauge covers the last retention window.

Which payments the round trip covers: only those where both parties' slates are stored on this relay, that is both parties use this relay as their receiving relay. A slate that is forwarded to another relay, or arrives from one and is answered through a forward, is not measured. Only slates that carry a txid count: invoices (I1) carry one but are answered without one (I2), so they stay in the unanswered gauge, and notices, contact traffic and pairing carry none. Transactions first seen before 0.1.10 have no start time and are skipped. The txid and the sender are kept in the same `txlinks` rows as before (two extra rows per transaction: who sent first and the first answer's time) and expire with them.

### Refusing a sender's host

`federation.deny_sender_hosts` is a list of plain host names (`"epicbox.example.org"`, no port, no scheme). Empty by default. A slate for a mailbox on this relay is refused when the host in its sender address (`es…@host[:port]`) matches an entry. Matching is exact on the whole host, ignores case and ignores the port. `example.org` does not match `sub.example.org`. An entry with a port or other characters makes `check-config` and the start fail. The list is read at start, like the rest of the config: edit it and restart.

Where it applies: every way a slate reaches a local mailbox: a wallet posting over the classic websocket, over mux/1 (`postslate`) or `POST /v1/post`, and a slate another relay forwards here (the sender address is kept as the wallet wrote it). Slates for mailboxes on other relays are forwarded as before; the relay they are for applies its own list.

What the sender sees: a protocol error, not a silent drop. Classic websocket: an `Error` frame (`InvalidRequest`, "This relay does not accept slates from <host>."). mux/1: an error frame with code `post_refused` and the same text. `/v1/post`: HTTP 403 with the text. When another relay forwarded the slate, the sender's own relay has already answered Ok, so the sender's wallet sees nothing; the forward is refused, retried a few times and then dropped.

Counting and logging: the counter `epicbox_denied_sender_host_total`, `posts_denied_host` in the traffic summary and `result="denied_sender_host"` on `epicbox_posts_total`. Each refusal also writes one `info` line with the host name only (no addresses, no IP), sampled like other lines: at most 10 a minute, with `suppressed` for the rest. The counter is exact.

Limits to know. The host part of a sender address is claimed by the sender's wallet. The slate's signature covers the slate, not that host. A wallet that writes another host in its address, or sends through another relay, is not stopped. The key part of the address is proven, but it is not what this list matches. So the option blocks slates that come from a named relay's address; it does not block a person, and it does not stop a determined one.

## 5. Backup and restore

The store is one SQLite file in WAL mode: `epicmail.db`, plus `epicmail.db-wal` and `epicmail.db-shm` while running. The WAL holds committed writes that are not yet in the main file.

Online backup, relay running:

```
sqlite3 /var/lib/epicmail/epicmail.db ".backup '/backup/epicmail-$(date +%F).db'"
```

Offline: stop the relay, then copy the `.db` file. Copy the `-wal` file with it if it exists. Never copy only the `.db` of a running relay.

Restore: stop the relay, put the backup file in place as `store.path`, remove old `-wal` and `-shm` files, start. Restoring an old backup drops messages posted since; senders got Ok for those. Prefer a recent backup.

A portable alternative is `epicmail export --config epicmail.toml --out file`, and `import` into a stopped or empty store. Export carries waiting messages with their 3.1.0 transaction ids, and queued forwards; it does not carry cancel records, used `/v1` challenges or mux/1 tokens. Mail is short lived (7 days), so a nightly backup is usually enough.

## 6. Retention and sweep

Messages nobody collects are deleted after `store.retention_days` (default 7, the protocol minimum). Collected messages are removed when the wallet acknowledges them (Made or Ack; wallets older than 2.0.0 send no Made, so theirs are removed on delivery). An expiry sweep runs at start and every 5 minutes. Once a day, at `store.vacuum_hour_utc` (UTC), an incremental vacuum returns every free page so the file shrinks, in rounds of 8 MiB with other writes in between. The file does not shrink before that vacuum, so a size peak after a flood falls back within a day. Deleted slates are overwritten in place where that costs no extra I/O (`secure_delete=FAST`); the rest is gone at the next vacuum or when SQLite reuses the page.

## 7. When to switch to Postgres

The store is single-writer SQLite. One writer thread collects pending writes and commits them as one transaction (group commit, at most `store.group_commit_max` per commit). A client gets Ok only after its commit. Readers use separate connections. This is simple and fast on one host, and it has one ceiling: the writer.

Stay on SQLite until one of these holds:

1. Sustained write rate near the single-writer ceiling. The ceiling depends on the host's CPU and disk; find it on your own host with `examples/loadgen.rs`, and act when the sustained rate stays above about half of it, not on peaks.
2. The database no longer fits in the page cache. Reads then hit disk and commit latency rises. Watch commit latency (`epicbox_store_commit_seconds`) against RAM.
3. More than one relay process must share one store (active-active, or a standby that takes over without a copy). SQLite cannot be shared safely by processes on different hosts.

Retention, mailbox caps and the 7 day limit keep the database small for most relays. A relay that meets none of the three gains nothing from Postgres. A backup and a cold standby restored from backup covers most availability needs.

## 8. Logging

The relay logs to two outputs, each with its own level and format:

- **stderr**, always: `log.level` and `log.format`. Under systemd journald keeps it
  (`journalctl -u epicmail`); in Docker, the container's log driver does.
- **a file**, on by default: `/var/log/epicmail/epicmail.log` at `trace` in JSON, rotated daily,
  compressed and pruned by the relay itself (below), so it needs no logrotate. When the relay
  cannot create or write it (run by hand without access to `/var/log`, say), it logs one
  warning on stderr and runs without the file; it never refuses to start because of it.

So by default the journal holds `info` and the file holds everything down to `trace`, for
looking back at what happened to one wallet or one message.

### Levels

| Level | What it holds |
|---|---|
| `error` | The relay cannot do its job: store reads or writes failing, a listener stopped, the store writer thread dying, a panic. Act on every one. |
| `warn` | Something bad outside the relay, or a capacity reached: a peer relay unreachable or refusing forwards, the store full (`store.max_bytes`), a network prefix sending more bad signatures or invalid posts in a summary interval than `log.warn_bad_requests`, the log file falling behind. |
| `info` | The startup line (identity, version, switches), drain and stop. The traffic summary (below). Expiry sweeps that removed messages, forwards or cancel records. Forwards delivered to another relay, sampled per peer. A slate refused because its sender's host is denied (below), sampled, with the host name only. Nothing per client. |
| `debug` | The life of each message: every post (client IP, shortened sender and recipient, size, message id, and stored, forwarded with the peer, or refused with the reason), every delivery and ack with its message id and shortened mailbox, every cancel, every forward attempt with the peer and the result. Each connection opened and closed, with the client IP, transport, duration and frame counts. |
| `trace` | All of `debug`, and every frame received (type and size), every Subscribe, Attach and Resume with its result or the reason it was refused, Made refused, Hold, Detach, cancels pushed to wallets, `/v1/pull` proofs, and every request a limit refused, with the client IP. |

A bare `debug` or `trace` applies to the relay only; the libraries (HTTP, websocket, TLS) stay
at `info`, because their own debug output can hold whole frames. A full filter such as
`"info,epicmail::forward=trace"` is used as written. `RUST_LOG` overrides `log.level` (stderr
only).

Sample lines (text format; the file's JSON holds the same fields):

```
DEBUG epicmail::relay::session: connected socket=7 ip=203.0.113.9
TRACE epicmail::relay::session: frame socket=7 frame="subscribe" bytes=212
TRACE epicmail::relay::session::classic: subscribed socket=7 mailbox=esYjKK…JDJd9y ver="3.1.0"
DEBUG epicmail::relay::post: post ip=203.0.113.9 from=esWQsH…T78BcP@relay.example:443 to=esYjKK…JDJd9y@relay.example:443 size=1873 id=zyFkKokdcpfGjpz3TvudT8PcUmljLWez result="stored"
DEBUG epicmail::relay::session::classic: delivered socket=7 mailbox=esYjKK…JDJd9y id=zyFkKokdcpfGjpz3TvudT8PcUmljLWez transport="classic"
DEBUG epicmail::relay::session::classic: acked socket=7 mailbox=esYjKK…JDJd9y id=zyFkKokdcpfGjpz3TvudT8PcUmljLWez transport="classic"
DEBUG epicmail::relay::session: disconnected socket=7 ip=203.0.113.9 transport="classic" duration_ms=48113 frames_in=9 frames_out=11
```

### Traffic summary

Every `log.summary_interval_s` (300 by default) the relay writes one `info` line with what
happened in that interval, but only when something changed since the previous line, so an idle
relay stays quiet:

```
INFO epicmail::traffic: traffic interval_s=300 posts_stored=152 posts_forwarded=2 posts_refused=30
  delivered=150 acked=148 cancels=0 logins_ok=412 bad_signatures=60 forwards_sent=2 forwards_failed=0
  limit_refusals=0 posts_denied_host=0 posts_txid=48 posts_no_txid=106 size_le_2560=61 size_le_5120=3 size_le_6144=52
  size_le_10240=38 size_over_10240=0 sockets=37 mailboxes_waiting=109 messages_waiting=159 forwards_waiting=0
  posts_stored_total=… posts_forwarded_total=… posts_refused_total=… delivered_total=… acked_total=…
  bad_signatures_total=…
```

(one line in the log). The counts are for the interval; `*_total` counts are since the start;
`sockets` and the `*_waiting` values are as they are now. `posts_refused` covers invalid posts,
limits, a full store, denied sender hosts and posts for a cancelled transaction (`posts_denied_host` counts the denied ones alone); `logins_ok` counts mailboxes proven
by Subscribe, mux/1 Attach or `/v1/pull`; `bad_signatures` counts every signature that did not
verify. `posts_txid` and `posts_no_txid` split the posts accepted in the interval by whether they carried an `epicboxtxid`; the `size_*` counts split the same posts by the size of the slate body (up to 2560, 5120, 6144 and 10240 bytes, and larger). A `/v1/pull` proof is a signature over `<challenge>@<domain>:<port>` of this relay, so a proof made for another relay counts here. `delivered` counts a redelivery again. The summary holds counts only.

At the same time, each network prefix (/24, /48) that sent more than `log.warn_bad_requests`
(30 by default; 0 turns it off) bad signatures, or more than that many invalid posts, in the
interval gets a `warn` line, sampled like the others:

```
WARN epicmail::traffic: many bad requests from one network suppressed=0 net=203.0.113.0/24
  bad_signatures=412 invalid_posts=0 interval_s=300
```

A wallet that signs the fixed first challenge (before 3.5.2) fails its Subscribe on every
connection, so a prefix with many such wallets can show up here too.

### Privacy

- **At `info`, `warn` and `error`** no line names a client: no IP, no address. Clients appear
  only as network prefixes in the bad-request warning; peer relays by `domain:port`.
- **At `debug` and `trace`** lines hold client IP addresses, shortened mailbox keys
  (`esYjKK…JDJd9y`: the first and last six characters, enough to follow one mailbox and to match
  a user's report, not enough to address mail), the domains in addresses, message ids, sizes and
  timing. That is personal data: a log at these levels shows who talked to whom and when. Keep
  such logs only as long as you need them (below), restrict who can read them (the log
  directory is `0750` for the service user), and do not share them.
- **Never, at any level:** full keys or addresses, slates, signatures, challenges, txids in full,
  resume tokens or any payload. Text from peer relays is stripped of control characters.
  `tests/log_privacy.rs` runs two relays through posts, deliveries, a cancel, a forward, a mux/1
  session and bad requests with both outputs at `trace`, and fails if a line holds any of these.

The log file is on by default, so a default install does log client IPs, to
`/var/log/epicmail/` for 14 days. To log no client IPs at all, keep `log.level` at `info` and set
`[log.file] enabled = false`, or its `level` to `info`; to keep them for less time, lower
`log.file.keep` (or use `rotate = "hourly"`).

Common fields: `socket` (a number local to the process), `ip`, `net`, `mailbox`, `from`, `to`,
`id`, `size`, `txid` (shortened), `peer`, `transport`, `limit`, `result`, `reason`, `error`,
`suppressed`.

### Floods

`warn` and `error` lines that a client or a failing dependency can repeat (store errors, forward
failures, peer refusals, bad-request warnings, a full store) are sampled: each call site writes
at most 10 lines a minute, and each line carries `suppressed`, the number dropped since the
previous one. Forwards delivered are sampled per peer relay at `info` in the same way. Exact
counts are in the traffic summary and the metrics (`epicbox_limit_refusals_total`,
`epicbox_forwards_total`, `epicbox_store_commit_errors_total`).

`debug` and `trace` are not sampled: each event is one line. Writing the file never slows the
relay: lines go through a queue of 16384 to a writer thread, and when the disk cannot keep up
the queue is full and new lines are dropped. Every 15 s the relay logs at `warn` how many lines
the file dropped, if any. Rotation by size (`max_size_mb`) and `keep` bound the disk the file
can use: at most `(keep + 1) × max_size_mb`, less with compression.

### Format

`"text"` writes one human-readable line per event, without colour codes unless stderr is a
terminal, and without a timestamp when stderr is connected to journald (journald stamps each
line). `"json"` writes one JSON object per line with the fields at the top level and a
`timestamp`, for a log shipper or `jq`.

### The log file

```toml
[log.file]
enabled = true
path = "/var/log/epicmail/epicmail.log"
level = "trace"
format = "json"
rotate = "daily"        # "hourly", "daily" or "size"
max_size_mb = 100       # with "size" the only trigger; otherwise also a cap per file
keep = 14               # rotated files kept
compress = true         # gzip rotated files
```

The systemd unit creates `/var/log/epicmail` for the service (`LogsDirectory=epicmail`); with
another path, make sure the service may write there (`ReadWritePaths=` in a drop-in, since the
unit runs with `ProtectSystem=strict`). The relay rotates the file at the turn of each UTC hour
or day, or before it grows past `max_size_mb`, to
`epicmail-<YYYYmmddTHHMMSS>Z.log`, gzips it in the background (`.log.gz`) when `compress` is
on, and deletes all but the newest `keep` rotated files. A file left from an earlier hour or day
is rotated when the relay starts. With `rotate = "daily"` and `keep = 14` the file holds about
two weeks, fewer when size rotations add files: `keep` counts them too, so a trace log that passes `max_size_mb` each day keeps less than 14 days. Read it with `jq`, for example the life of one message:

```
zcat -f /var/log/epicmail/epicmail*.log* | jq -c 'select(.id == "zyFkKokdcpfGjpz3TvudT8PcUmljLWez")'
```

### Rotation and retention

- **The log file** rotates, compresses and prunes itself (above). For two weeks of history,
  `rotate = "daily"` and `keep = 14`.
- **journald.** journald rotates on its own; set the size and age it keeps in
  `/etc/systemd/journald.conf.d/epicmail.conf`, for example:

  ```
  [Journal]
  SystemMaxUse=500M
  MaxRetentionSec=14day
  ```

  then `systemctl restart systemd-journald`. The unit file also sets a per-service rate limit
  (`LogRateLimitIntervalSec`, `LogRateLimitBurst`) as a backstop to the relay's own sampling. With
  `log.level` at `debug` or `trace` the journal holds client IPs too; set its retention
  accordingly.
- **Docker.** The default `json-file` driver does not rotate. Use the `local` driver, which
  does, or set limits:
  `docker run --log-driver local --log-opt max-size=20m --log-opt max-file=5 ...`.
- **stderr to a file of your own.** Rotate it with logrotate and `copytruncate`, since the relay
  keeps stderr open. `[log.file]` is simpler.

Fourteen days is a reasonable default for relay logs. The reverse proxy's access log holds full
client IP addresses too: keep it as short, or use a log format without `$remote_addr` (nginx) if
you do not need it.

## 9. Upgrade and roll back

The database records its schema version. A binary opens only a database of its own schema
version and refuses any other at start, so a mismatch stops the relay before it touches data.
The schema has been version 1 since the first release.

Upgrade:

1. Back up the store (section 5).
2. Run `epicmail check-config` with the new binary against the current file. Unknown or
   removed keys are refused, so this shows any config change the new version needs.
3. Replace the binary and restart. SIGTERM drains sockets with close code 1001; wallets
   reconnect on their own. Messages in flight at the restart are offered again when their
   lease ends (at most 60 s, or a mux/1 Hold's end). mux/1 resume tokens live in memory, so
   mux/1 clients attach again with signatures.
4. Check the startup line in the log and `/ready`.

Roll back: stop the relay and put the old binary back. `tools/install.sh` keeps it as `/usr/local/bin/epicmail.prev` (next to the installed binary) when it replaces one: copy that file over `/usr/local/bin/epicmail`. When the schema version did not change
(the release notes say when it does), start it on the same database. When it did, restore the
backup from step 1 (messages posted since are lost), or `export` with the new binary and
`import` with the old one: import ignores fields it does not know.

## 10. Shipping a change (maintainers)

`tools/ship` takes the working tree to the live relay, `epicmail.btlabs.uk` (it also answers as its alias `epicbox.btlabs.uk`, which the script checks), and checks the result.

```
tools/ship                       # ship this checkout
tools/ship --src DIR             # ship another checkout
tools/ship --rollback            # swap back to epicmail.prev
```

Steps, with timings printed at the end:

1. Lane A: rsync the tree to hostinger-2, build x86_64 musl with `cargo zigbuild --release` into a persistent target dir (`~/epicmail-fast/src/target`), check that the binary is static.
2. Lane B, in parallel: `cargo test --locked` on this machine, under `hagen-heavy`.
3. Deploy: `tools/ship-deploy.sh` on the relay installs the binary as `/usr/local/bin/epicmail.new`, runs `--version` and `check-config` against the live config, keeps the old binary as `epicmail.prev` (a hard link), renames the new one over `epicmail` and restarts the unit.
4. Verify: `tools/ship-probe.py` checks `/health`, `/ready`, `/status.json`, the landing page and a websocket Challenge and GetVersion, on the host and again through the public URL. The host check also needs no self-restarts, the running binary's hash (read from `/proc/PID/exe`) to equal the new one, and no journal errors or panics after the restart.

Any failed check puts `epicmail.prev` back, restarts, checks again and says so (exit status 3). A warm run takes about one minute; the first run into an empty target dir takes about two.

What ships is the working tree, uncommitted changes included. The first line of the output names the commit and whether the tree is dirty. Ship from the tree that matches the live line.

### Release (slow path)

```
tools/ship --release X.Y.Z       # background; the fast path stays usable
tools/ship --publish X.Y.Z       # sign and create the GitHub release
```

`--release` needs a clean tree, `Cargo.toml` at X.Y.Z and tag `vX.Y.Z` at HEAD. It builds in a separate dir on the relay host (`~/epicmail-build/src`, niced), runs the full test suite, builds the three binaries (linux x86_64, linux aarch64, windows x86_64) and writes `SHA256SUMS`, all under `~/.cache/epicmail-ship/release-X.Y.Z/`. Follow `job.log` there. `--dry-run` stops before staging.

`--release` also copies `tools/install.sh` and the two packaging files `get.sh` uses into the staged files and lists them in `SHA256SUMS`, so `get.sh` can check them.

`--publish` signs `SHA256SUMS` with the BT Labs key (`~/.config/btlabs/signing/btlabs-2026-a.key`, or `SHIP_SIGN_KEY`) through `tools/ship-sign.py`, checks the signature against the public key pinned in `tools/get.sh`, checks every hash and runs `gh release create`. Nothing is published by `--release`.

## 11. The ICP store

With `[store.icp]` set, the relay keeps its mail in an ICP store canister (epicbox-store, the
canister behind icpepicbox.btlabs.uk) instead of the SQLite file. The
wallet protocols, federation and `/v1` stay the relay's; the canister holds messages,
forwards, cancel records and the caps. [icp-mailbox.md](icp-mailbox.md) has the design.

The binary needs the `icp` feature: `cargo build --release --features icp`. A build without it
refuses a config that sets `[store.icp]`.

```toml
[store.icp]
canister = "<canister id>"
identity_pem = "/etc/epicmail/icp-frontend.pem"   # secp256k1 or Ed25519; read once at start
url = "https://icp-api.io"                         # default
poll_ms = 1000                                     # reads of the canister's change log
batch_ms = 200                                     # acks and forward results held for one call
call_timeout_s = 30                                # one call, retries included
```

`local_replica = true` is for PocketIC or dfx only: it trusts the replica's root key and allows
an `http://` url.

Set up the canister once, as a controller:

1. `set_frontends(vec { principal "<front-end principal>" })`. The relay logs the principal of
   its identity on the `icp store` line at start.
2. `set_local_domains(vec { "<server.domain>:443" })`: the domains this mailbox answers for.
3. Optionally `set_max_bytes(<bytes>)`.

At start the relay checks the canister's front-end API version, reads a snapshot of the waiting
messages' metadata into memory, then follows the canister's change log every `poll_ms`. Mail
posted to the canister directly (its own `/v1`, other canisters) reaches the relay's sockets
within `poll_ms`. Bodies are fetched when a message is offered.

What differs from SQLite:

- **Caps are the canister's.** 200 messages per mailbox, 20 per sender and mailbox, 128 KiB per
  message, and its own byte cap. `limits.queue_cap`, `limits.per_sender_cap` and
  `store.max_bytes` do not apply. Retention is the canister's 7 days.
- **Acknowledgements are batched.** A Made or Ack removes the message from the relay's view at
  once and reaches the canister within `batch_ms`; so do forward results. A shutdown sends what
  is held. `/status.json` counts can lag by `batch_ms`.
- **Leases live in the relay's memory.** After a restart a message can be offered again before
  its 60 s lease ends. Wallets handle a repeat.
- **Reads are uncertified queries**, answered by one replica. The relay checks each body against
  its sender's signature before it sends it, so a replica cannot forge mail. The canister trusts
  the front-end's key for reads and acknowledgements.
- **No local data.** `sweep` and `vacuum` are the canister's; `import` and `export` refuse a
  config with `[store.icp]`; backups are canister snapshots.
- **Each update call costs cycles**: a post, a forward, a cancel, and one call per batch of
  acknowledgements or forward results. Queries cost the canister cycles too.

Upgrade and roll back the canister with a snapshot (`dfx canister snapshot create`, then
`snapshot load`). The relay's own upgrade is as in section 9, without the database steps.

Tests: `tools/icp-local` runs a local PocketIC with a store canister per request. With
`POCKET_IC_BIN` (the pocket-ic server) and `EPICMAIL_TEST_ICP_WASM` (the canister wasm) set,
`EPICMAIL_TEST_STORE=icp cargo test --features icp --test loopback` runs the loopback suite on
the ICP store. Three tests that need the SQLite file or a later clock skip there.
