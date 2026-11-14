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
  -v /etc/epicmail/epicmail.toml:/etc/epicmail/epicmail.toml:ro \
  epicmail
```

In the container config set `server.listen = "0.0.0.0:3423"` and `store.path = "/data/epicmail.db"`. The image runs as uid 65532 on a `scratch` base and has no shell, so there is no HEALTHCHECK. Check from outside instead: `curl -fsS http://127.0.0.1:3423/ready` from the host or the reverse proxy, or a Compose/orchestrator probe on `/ready`. Stop with `docker stop -t 30`: the default 10 s equals `drain_seconds`.

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
| `bytes_per_min_per_ip` | 16 MiB | Disk fill by few large posts |
| `frames_per_min_per_socket` | 1200 | One chatty socket using CPU |
| `queue_cap` | 2000 | One mailbox growing without bound |
| `per_sender_cap` | 200 | One sender filling a mailbox |
| `sockets_per_ip` | 256 | One prefix using all sockets |
| `sockets_per_address` | 4 | Many sockets on one address |
| `failed_sigs_per_min_per_ip` | 120 | Signature guessing, CPU burn on verification |
| `mux_mailboxes_per_socket` | 256 | One mux/1 socket attaching everything |
| `mux_attach_per_frame` | 64 | Large attach frames |
| `mux_inflight` | 32 | Mail pushed on one mux/1 socket and not yet acked or held |
| `mux_attach_frames_per_min` | 30 | Attach/detach churn |
| `ipv4_prefix` / `ipv6_prefix` | 24 / 48 | Sets how clients are grouped for per-IP limits |
| `max_sockets` | 150000 | Total file descriptors and memory |
| `shared_sources` | empty | Tor exits and the onion loopback being limited as one client |
| `shared_multiplier` | 16 | Factor applied for `shared_sources` |
| `mux_sockets_per_ip` | 64 | One prefix holding many mux/1 sockets |

`queue_cap` and the retention below bound database size: roughly `addresses × queue_cap × message size` in the worst case.

## 4. Reading the health endpoints

- `/health`: the process is up and answering. Use it for liveness. It does not look at the store.
- `/ready`: the store is writable. Use it for load balancer and orchestrator checks. A failure means the disk is full or read-only, or the DB file is damaged. During a SIGTERM drain it may also report not ready.
- `/metrics`: Prometheus text, metric names start with `epicbox_`. Look first at open sockets (against `max_sockets`), posts accepted and rejected (rejects by limit name show which limit fires), write queue depth and commit latency, and federation deliveries and failures. When `server.metrics_listen` is unset, it is served on `server.listen` to loopback peers whose request carries no `X-Forwarded-For`, so requests that came through the reverse proxy get 404. Set `server.metrics_listen` to serve it on a separate address instead, for example a private one a scraper on another host can reach.
- `/status.json`: a small JSON summary for people and status pages: name, version, sockets, queue totals, uptime. It is public; it holds no per-address data.
- `/.well-known/epicbox.json`: the info document wallets and peers read: software and version, `server.name`, identity (`domain:port`), protocol versions, whether federation is on, and the mux/1 and HTTPS features with their limits.

## 5. Backup and restore

The store is one SQLite file in WAL mode: `epicmail.db`, plus `epicmail.db-wal` and `epicmail.db-shm` while running. The WAL holds committed writes that are not yet in the main file.

Online backup, relay running:

```
sqlite3 /var/lib/epicmail/epicmail.db ".backup '/backup/epicmail-$(date +%F).db'"
```

Offline: stop the relay, then copy the `.db` file. Copy the `-wal` file with it if it exists. Never copy only the `.db` of a running relay.

Restore: stop the relay, put the backup file in place as `store.path`, remove old `-wal` and `-shm` files, start. Restoring an old backup drops messages posted since; senders got Ok for those. Prefer a recent backup.

A portable alternative is `epicmail export --config epicmail.toml --out file`, and `import` into a stopped or empty store. Mail is short lived (7 days), so a nightly backup is usually enough.

## 6. Retention and sweep

Messages nobody collects are deleted after `store.retention_days` (default 7, the protocol minimum). Collected messages are removed when the wallet acknowledges them (Made or Ack; wallets older than 2.0.0 send no Made, so theirs are removed on delivery). An expiry sweep runs at start and every 5 minutes. Once a day, at `store.vacuum_hour_utc` (UTC), an incremental vacuum returns free pages so the file shrinks. The file does not shrink before that vacuum, so a size peak after a flood falls back within a day.

## 7. When to switch to Postgres

The store is single-writer SQLite. One writer thread collects pending writes and commits them as one transaction (group commit, at most `store.group_commit_max` per commit). A client gets Ok only after its commit. Readers use separate connections. This is simple and fast on one host, and it has one ceiling: the writer.

Stay on SQLite until one of these holds:

1. Sustained write rate near the single-writer ceiling: about 2,000 messages per second end to end on an 8-core desktop with NVMe (docs/loadtest.md). Measure your own host before relying on it. Act when the sustained rate stays above about half of it, not on peaks.
2. The database no longer fits in the page cache. Reads then hit disk and commit latency rises. Watch commit latency (`epicbox_store_commit_seconds`) against RAM.
3. More than one relay process must share one store (active-active, or a standby that takes over without a copy). SQLite cannot be shared safely by processes on different hosts.

Retention, mailbox caps and the 7 day limit keep the database small for most relays. A relay that meets none of the three gains nothing from Postgres. A backup and a cold standby restored from backup covers most availability needs.
