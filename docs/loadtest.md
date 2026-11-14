# Load test

Measured on 2026-11-14 on one development host. The relay and the load generator ran on the same machine. The machine was also running other build and test jobs (load average 7 to 12 on 16 threads), so the figures are a lower bound for a quiet host.

| | |
|---|---|
| CPU | AMD Ryzen 7 4800H, 8 cores, 16 threads |
| Disk | NVMe SSD, ext4 |
| Kernel | Linux 6.17 |
| Relay | release build, `cargo build --release`, SQLite WAL with `synchronous=FULL` (Ok is sent after fsync) |
| Load generator | `examples/loadgen.rs`, release build |

## Method

`loadgen` opens listener sockets and subscribes one key on each (classic 3.0.0 Subscribe with a signed challenge). It then opens sender sockets and posts signed PostSlate frames at a fixed total rate to random listeners. Each payload carries a send timestamp, so the listener side measures delivery latency (from just before PostSlate to receipt of the Slate frame). Listeners answer each Slate with Made, as a wallet does, and answer each interval Challenge with Subscribe. Clients are spread over 250 source /24 prefixes on loopback (127.1.x.y for senders, 127.2.x.y for listeners), so the per-prefix limits see a spread of networks. Relay RSS and CPU are read from `/proc` every 10 s.

Each scenario starts with an empty database. The payload is 2 KiB, which is about the size of a real encrypted slate. After posting stops, the generator waits for outstanding deliveries (`--drain`) and then counts what never arrived.

To repeat a run:

```sh
cargo build --release --bin epicbox-relay --example loadgen
target/release/epicbox-relay --config relay-load.toml serve &
target/release/examples/loadgen --pid $! --listeners 10000 --senders 1000 --rate 1000 --duration 60
```

`relay-load.toml` is a plain config (listen `127.0.0.1:3430`, domain `loadtest.local`, federation off). The runs above 500 posts/s raise the per-prefix post limits (see "Limits" below).

## Results

| Scenario | Listeners | Posts/s target | Posts/s accepted | Lost | Duplicates | Post Ok p50 / p99 | Delivery p50 / p99 | Relay RSS | Relay CPU |
|---|---|---|---|---|---|---|---|---|---|
| Idle | 20,000 | 0 | n/a | n/a | n/a | n/a | n/a | 307 MiB | 0 to 17%, 62% at the interval challenge |
| Steady, default limits | 10,000 | 500 | 499 | 0 | 0 | 3.1 / 494 ms | 6.0 / 694 ms | 160 to 215 MiB | 80 to 90% |
| Steady | 10,000 | 1,000 | 990 | 0 | 0 | 5.2 / 328 ms | 9.9 / 522 ms | 159 to 233 MiB | 115 to 135% |
| Near ceiling | 5,000 | 2,000 | 1,815 (2,000 in steady state) | 0 | 0 | 13 / 49 ms | 25 / 86 ms | 87 to 144 MiB | 180% |
| Overload | 5,000 | 4,000 | 1,630 | 0 | 0 | 2,252 / 3,429 ms | 16 / 36 s | 87 to 276 MiB | 115 to 150% |

"Lost" counts posts that got Ok and never reached the listener by the end of the drain. In every run it was 0, and no listener saw the same message twice. No post was refused and none timed out, apart from the smoke run below, which shows the per-prefix limit.

Connecting and subscribing 20,000 listeners took 5.3 s. 10,000 took 1.4 to 2.3 s.

### Memory per socket

An idle subscribed socket costs about 15 KiB of relay RSS (20,000 sockets: 307 MiB; 5,000: 87 MiB; the process alone: 10 MiB). The first run measured 136 KiB per socket: the websocket library's default 128 KiB read and write buffers were allocated for each socket. The relay now sets an 8 KiB read buffer (it grows for a large frame) and writes each frame at once. At `max_sockets = 150000` that is about 2.3 GiB for idle sockets.

### Throughput ceiling

The ceiling is the single SQLite writer. Each message costs two commits' worth of work: the insert before Ok, and the delete when the listener answers Made. Group commit batches both. On this host the relay held 2,000 messages per second end to end (posted, stored, delivered, acknowledged and deleted) with p99 under 100 ms. At a 4,000/s target it accepted about 1,700 posts/s, and deliveries fell behind posts at about 1,000/s. Clients then waited longer for Ok (p50 2.3 s), which slowed the senders. Nothing was lost, refused or delivered twice, and the backlog drained after posting stopped. Overload shows up as latency, which `/metrics` reports as commit latency and write queue depth.

Posts are far below the ceiling, so idle sockets, not posts, set the relay's size.

### Tail latency

At 500 and 1,000 posts/s the p99 of post Ok (330 to 490 ms) is higher than at 2,000 posts/s (49 ms). The low-rate runs used 10,000 listeners instead of 5,000. The cause was not isolated. Candidates are WAL checkpoints done by the writer thread, the interval challenge reaching all listeners at once, and other jobs on the shared host competing for CPU and disk. If tail latency matters on the production host, a background checkpoint thread is the change to try.

### Limits

With default limits, one /24 may post 240 times a minute (burst 480). The smoke run (10 senders on 10 prefixes, 100 posts/s, so 600 a minute per prefix) accepted the burst and then refused the rest with `Rate limit exceeded; retry in 1 s.`: 1,391 accepted, 618 refused. Every accepted post was delivered. That is the limit doing its job. With 250 prefixes the default limits allow 1,000 posts/s in total, so the 1,000/s and higher runs used `relay-load-hi.toml` with the per-prefix post, byte and frame limits raised.

## Not measured

- TLS. Production relays sit behind a reverse proxy that ends TLS, so the relay itself never does TLS for clients.
- Federation under load. Forwarding to a peer was tested for correctness (`tests/loopback.rs`, `tools/compat-classic.sh`), not for throughput.
- mux/1 sockets carrying many mailboxes. Memory per mailbox on a mux/1 socket is a registry entry, smaller than a socket.
- Long runs (hours) and a large store (millions of waiting messages).
- A host other than this one. The production VPS has fewer cores and a slower disk, so measure it there before relying on the ceiling.
