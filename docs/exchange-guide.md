# Epicmail for exchanges: moving epicbox.nonkyc.io from the Node Epicbox

## 1. Overview

Epicmail is a relay for Epic Cash wallets. It carries the slates that two wallets pass back and forth before a transaction goes on chain. It replaces the Node Epicbox and its MongoDB on one host.

For the exchange, the relay software and its storage change. The protocol, the wallets, the Epicbox address `epicbox.nonkyc.io:443` and the nginx in front stay the same. Slates still waiting in Mongo are exported and imported, so nothing in flight is dropped at the cut-over.

This guide has four parts: the move (section 2), how the exchange wallet cancels transactions (section 3), what LEPIC and BT Wallet add (section 4) and links (section 5). Section 3 applies whichever relay is used.

## 2. Step by step

Run the commands as a user with `sudo`, on the relay host. Replace values in `CAPITALS` or `<angle brackets>`.

### Step 1. Keep deposits and withdrawals closed

Keep both closed from the start of this guide until the checks in step 10 pass.

### Step 2. Check what listens on port 3423

```sh
sudo ss -ltnp | grep 3423
```

The old relay listens on all interfaces (`*:3423` or `0.0.0.0:3423`). Epicmail listens on `127.0.0.1:3423` only, and nginx is the only public entry.

From another machine, this should time out:

```sh
nc -vz -w 3 epicbox.nonkyc.io 3423
```

If it connects, close port 3423 in the firewall (for ufw: `sudo ufw deny 3423/tcp`). nginx reaches the relay on `127.0.0.1`, so closing it changes nothing for users.

### Step 3. Back up the nginx site

Find the file that serves `epicbox.nonkyc.io`:

```sh
sudo grep -rl epicbox.nonkyc.io /etc/nginx
```

Set `SITE` to the real path (not a symlink: `readlink -f` shows it) and copy it:

```sh
SITE=/etc/nginx/sites-available/epicbox.nonkyc.io
sudo cp -a "$SITE" "$SITE.pre-epicmail"
```

### Step 4. Install the tools the move needs

`minisign` checks the release signature. The install stops without it. `mongosh` is the Mongo shell the exporter calls, and `python3` runs the exporter.

```sh
sudo apt install minisign python3
command -v mongosh
```

If the second command prints nothing, install `mongosh` from MongoDB's own repository (https://www.mongodb.com/docs/mongodb-shell/install/).

### Step 5. Stop the old relay and export its waiting slates

Stopping the old relay first means no new slate can arrive during the export. Leave `mongod` running.

```sh
sudo systemctl stop epicbox
```

Download the exporter. It reads Mongo and changes nothing.

```sh
curl -fsSLo ~/export-node-mongo.py https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/export-node-mongo.py
```

Export. `MONGO_URL` is the `mongo_url` in the old relay's `config.json`. The exporter writes the slates to the file and a summary to the screen.

```sh
python3 ~/export-node-mongo.py --uri "MONGO_URL" > ~/waiting-slates.jsonl
```

Look at the summary: `slate` is the number of slates written, and `skipped_*` counts rows it could not use. The exit code is 0 when nothing was skipped.

The connection string is visible in the process list while the export runs, so run it on the relay host. The file holds encrypted slates and addresses. Keep it readable by the admin only.

<details>
<summary>For advanced users: what the exporter reads</summary>

It reads the `slates` collection of the `epicbox` database (override with `--db` and `--collection`). It exports documents with `made: false` newer than the Node relay's own 7-day expiry. `--ttl SECONDS` changes that age, `--now ISO_TIMESTAMP` is for tests on old data. Rows with a bad recipient key or a damaged payload are skipped and counted. The output format is the one `tools/export-node-pg.py` writes and `epicmail import` reads. The Node relay's Mongo store has no forward queue, so none is exported.
</details>

### Step 6. Install Epicmail

`--no-tls` leaves TLS to the existing nginx. The script checks the release signature and the binary's checksum before it installs anything.

```sh
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh -s -- --domain epicbox.nonkyc.io --no-tls
```

It installs the `epicmail` service, writes `/etc/epicmail/epicmail.toml` and starts the relay on `127.0.0.1:3423`. The last lines say to put a TLS proxy in front. That is step 8.

### Step 7. Check the config

```sh
epicmail check-config --config /etc/epicmail/epicmail.toml
sudo systemctl status epicmail --no-pager
```

The defaults fit an exchange. The file is a copy of [packaging/epicmail.example.toml](../packaging/epicmail.example.toml) with the domain set.

<details>
<summary>For advanced users: settings worth knowing</summary>

- `limits.posts_per_min_per_address` and `limits.posts_burst_per_address` (60 and 120): the hot wallet posts one slate per deposit reply and one per withdrawal. A batch of more than 120 withdrawals at once is refused above the burst. Raise both (for example 600 and 1200) if withdrawals go out in batches.
- `limits.sockets_per_address` (4): a fifth listener on the same address closes the oldest.
- `store.retention_days` (7): the minimum, and the same as the old Mongo expiry.
- `protocol.cancel` (true): see section 3 before changing it.

After an edit, run `check-config` again and `sudo systemctl restart epicmail`.
</details>

### Step 8. Replace the nginx site

The old site only proxies to port 3423, which Epicmail now serves, so it already works. The full example adds per-address limits, a 404 on `/metrics`, long WebSocket timeouts and the `/v1/` location.

Download it and fill in the domain:

```sh
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/packaging/nginx.example.conf | sed 's/relay\.example\.org/epicbox.nonkyc.io/g' > ~/epicbox.nonkyc.io.conf
```

Check that the two `ssl_certificate` lines in it name the certificate files the old site used:

```sh
grep ssl_certificate ~/epicbox.nonkyc.io.conf
sudo grep ssl_certificate "$SITE"
```

If the paths differ, edit the `ssl_certificate` and `ssl_certificate_key` lines in `~/epicbox.nonkyc.io.conf` to the old ones. Then replace the site, test and reload:

```sh
sudo cp ~/epicbox.nonkyc.io.conf "$SITE"
sudo nginx -t && sudo systemctl reload nginx
```

The file has `map` and `limit_*_zone` lines that must sit in the `http` context. Files in `sites-enabled` and `conf.d` are included there. If another site already defines a zone with the same name, `nginx -t` says so.

### Step 9. Import the waiting slates

```sh
sudo epicmail import --config /etc/epicmail/epicmail.toml ~/waiting-slates.jsonl
```

It prints a summary. `slates` should equal the `slate` count from step 5. Running it again is harmless: slates already present are counted as `duplicates`.

The exchange wallet's listener receives imported slates the next time it subscribes.

### Step 10. Check

The relay answers:

```sh
curl -s https://epicbox.nonkyc.io/ready
curl -s https://epicbox.nonkyc.io/.well-known/epicbox.json | grep -o '"identity":"[^"]*"'
```

Expected: `{"ready":true}` and `"identity":"epicbox.nonkyc.io:443"`.

Queue and sockets (the exchange wallet's listener should count as a socket within a minute or two):

```sh
curl -s https://epicbox.nonkyc.io/status.json
```

Then test with a separate wallet that uses the same Epicbox domain: send a small deposit to the exchange wallet and receive a small withdrawal from it. Both must complete and confirm on chain.

To follow a payment, the relay keeps a detailed log file (path `/var/log/epicmail/epicmail.log`, each post, delivery and acknowledgement with a message id):

```sh
sudo tail -f /var/log/epicmail/epicmail.log
```

Open deposits and withdrawals again only after both test payments confirm.

### Step 11. Disable the old relay and Mongo

Both must stay off, or after a reboot two relays compete for port 3423.

```sh
sudo systemctl disable --now epicbox mongod
```

Keep the Mongo data directory for now. It is the way back (next step).

### Rollback

Stop Epicmail and disable it, so it does not return after a reboot:

```sh
sudo systemctl disable --now epicmail
```

Put the old nginx site back:

```sh
sudo cp -a "$SITE.pre-epicmail" "$SITE"
sudo nginx -t && sudo systemctl reload nginx
```

Start the old relay and Mongo again:

```sh
sudo systemctl enable --now mongod epicbox
```

Slates that were waiting on Epicmail at that moment are not in Mongo, and no tool loads them there. To see how many there are before the switch back:

```sh
curl -s http://127.0.0.1:3423/status.json | grep -o '"messages_waiting":[0-9]*'
```

`sudo epicmail export --config /etc/epicmail/epicmail.toml --out ~/epicmail-waiting.jsonl` saves them to a file. The senders of these slates can send them again.

### After the move

**Log level.** The log file starts at `trace`, which records every frame and the wallet's protocol version. Keep it for the first days, then lower it. `debug` still keeps every post, delivery, acknowledgement and cancel with its message id. Edit `/etc/epicmail/epicmail.toml`:

```toml
[log.file]
level = "debug"
```

```sh
epicmail check-config --config /etc/epicmail/epicmail.toml && sudo systemctl restart epicmail
```

The file rotates, compresses and prunes itself (daily, 14 files, 100 MB each at most). Trace and debug lines hold client IP addresses for as long as the files are kept.

**journald.** Cap the journal so it does not grow:

```sh
sudo mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=500M\nMaxRetentionSec=14day\n' | sudo tee /etc/systemd/journald.conf.d/epicmail.conf
sudo systemctl restart systemd-journald
```

**Upgrades.** Run the installer again without `--domain`. It backs up the store, checks the config with the new binary, restarts only when something changed and checks `/ready`.

```sh
curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh -s -- --no-tls
```

**Metrics.** Prometheus metrics are served on the loopback address only. nginx answers 404 for `/metrics`.

```sh
curl -s http://127.0.0.1:3423/metrics | grep -E 'epicbox_(roundtrip_unanswered|limit_refusals_total)'
```

`epicbox_roundtrip_unanswered` counts payments whose first slate has had no answer for 24 hours. It is a useful alert for stuck deposits.

### If Cloudflare is turned on later

`epicbox.nonkyc.io` is DNS-only today, so nginx sees real client addresses and nothing here is needed. With the Cloudflare proxy on, nginx sees a Cloudflare address for every user. Epicmail groups clients by network, so all users behind one Cloudflare range would share one set of limits, and a ban would hit Cloudflare.

Put these lines in the `http` context of nginx, before the server blocks (a file in `/etc/nginx/conf.d/` works). This command writes them with Cloudflare's current ranges:

```sh
{ curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6; } | awk 'NF { print "set_real_ip_from " $1 ";" } END { print "real_ip_header CF-Connecting-IP;" }' | sudo tee /etc/nginx/conf.d/cloudflare-realip.conf
sudo nginx -t && sudo systemctl reload nginx
```

The file starts with lines like `set_real_ip_from 173.245.48.0/20;` and ends with `real_ip_header CF-Connecting-IP;`. Cloudflare's range list changes now and then: run the command again to refresh it.

Leave the server block as shipped (`proxy_set_header X-Forwarded-For $remote_addr;`). With these lines `$remote_addr` is the visitor, so Epicmail's limits and nginx's limit zones work per visitor. Allow port 443 from Cloudflare ranges only, or anyone can send a forged `CF-Connecting-IP`. Do not add Cloudflare ranges to `server.trusted_proxies`.

### Bans

Epicmail has no ban list. A ban script can add addresses to an nftables set, which drops them before TLS. Put this in `/etc/nftables.d/epicmail-ban.nft` (or load it with `sudo nft -f`):

```
table inet epicmail_ban {
    set banned4 {
        type ipv4_addr
        flags interval, timeout
        timeout 24h
    }
    set banned6 {
        type ipv6_addr
        flags interval, timeout
        timeout 24h
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @banned4 drop
        ip6 saddr @banned6 drop
    }
}
```

The script then adds addresses or networks:

```sh
sudo nft add element inet epicmail_ban banned4 '{ 203.0.113.0/24 }'
sudo nft add element inet epicmail_ban banned6 '{ 2001:db8::/48 timeout 1h }'
```

Entries expire after 24 hours unless a `timeout` is given. This works when the real client address reaches the host, that is with Cloudflare off. With Cloudflare on, ban in Cloudflare's own rules, or in nginx with a `deny` include and `nginx -s reload`.

When the relay sees many bad requests from one network, it logs a warning that names it (`many bad requests from one network`, with `net=`). At the default level this is in the journal: `sudo journalctl -u epicmail | grep 'bad requests'`.

### Refusing payments sent from a named relay

NonKyc.io's rules do not allow miners to pay deposits straight from a mining pool's Epicbox. To refuse slates whose sender address names the pool's relay, list its host in `/etc/epicmail/epicmail.toml` and restart:

```toml
[federation]
deny_sender_hosts = ["pool-epicbox.example.org"]   # the pool relay's host name, no port
```

Then `sudo epicmail check-config --config /etc/epicmail/epicmail.toml` and `sudo systemctl restart epicmail`. The list is read at start. Matching is exact on the host, ignores case and ignores the port.

A sender on a listed host gets a protocol error ("This relay does not accept slates from <host>.") and the slate is not stored. This holds for slates posted directly and for slates another relay forwards to yours. When the pool's relay forwards, it has already told the miner's wallet Ok, so the pool side sees the refusal only as a failed forward. Refusals are counted: `epicbox_denied_sender_host_total`, and `posts_denied_host` in the traffic summary. Each refusal logs one `info` line with the host only.

What this does not do: the host in a sender address is written by the sender's wallet and is not covered by the slate's signature. A wallet that puts another host in its address, or pays through another relay, is not stopped. The option blocks slates that name a relay, not a person. For the details, see "Refusing a sender's host" in [the operating guide](https://github.com/BTLabsUK/epicmail/blob/main/docs/operating.md).

## 3. Cancels while 4.x wallets are in use

This section is about the exchange's own wallet, whatever relay it uses. Epicmail changes none of it.

### What happens

The wallets in use today are epic-wallet 4.0.x and 4.1.x (CLI and owner API), and apps built for Epic Cash such as Epic Pay, Stack Wallet and the Epic GUI wallet. This section describes epic-wallet 4.1.0, the latest release when this was written (checked in its source).

- A transaction is cancelled in a wallet by `cancel_tx`, by the TTL (time to live) check on refresh, or by `scan` with `-d`.
- A cancel checks the type of the entry and that it is not yet confirmed in the wallet. It does not ask the node whether the transaction is in the pool or on chain.
- A cancel deletes the transaction's unconfirmed outputs (the output of a deposit, the change of a withdrawal) and unlocks its inputs.
- A transaction that was finalized and posted, and is waiting for a block, can still be cancelled this way. If a block then includes it, the wallet's next scan finds an output it has no record of and adds it as a new entry: type "Received", address field `Restore`, no slate id, no kernel.
- The original entry stays cancelled. The scan does not link the two.

In a deposit, the exchange's wallet cancels what it received, and later the sender's transaction is mined: the log shows a cancelled deposit and a `Restore` entry for the full amount. In a withdrawal, the log shows `Sent (Cancelled)` although the recipient was paid, and a `Restore` entry for the change. Re-sending such a withdrawal pays the recipient twice.

Slow block periods make the gap between "posted" and "confirmed" longer, and a cancel timer fires inside it more often.

### Practice

**1. Check the kernel on the node before any cancel.** Get the kernel excess of the transaction from the wallet (`Kernel Excess` in the detail view; the ID is the number in the first column of `epic-wallet txs`):

```sh
epic-wallet txs -i ID
```

Check the pool and the chain on the node. `NODE` is the node's API address (`api_http_addr` in the node's config) and `EXCESS` the kernel excess in hex. If the node uses an API secret, add `-u epic:SECRET` to both commands.

```sh
NODE=http://127.0.0.1:3413
EXCESS=<kernel excess>
curl -s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_unconfirmed_transactions","params":[]}' $NODE/v2/foreign | grep -c "$EXCESS"
curl -s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_kernel","params":["'$EXCESS'",null,null]}' $NODE/v2/foreign
```

The first command prints a number above 0 when the kernel is in the pool. The second returns `"Ok"` with a height when the kernel is on chain, and an error when it is not found. A hit in either means: do not cancel.

**2. Never run `scan -d` while transactions are in flight.** `scan -d` (`--delete_unconfirmed`) cancels every transaction that is not yet on chain, which includes all those waiting in the pool.

**3. Reconcile by kernel or output commitment, not by slate id.** The slate id is on the cancelled entry only. At receive time, record the entry ID, the kernel excess, the amount and the output commitments (`epic-wallet txs -i ID` lists the outputs with their commitments). Record them before a cancel, because a cancel deletes the output. A `Restore` entry's output has the same commitment, so it can be matched back to the record.

**4. Do not re-send a cancelled withdrawal** until `get_kernel` has found nothing for its kernel for a long time (at least a day of blocks). A kernel that shows up later means the user was paid.

**5. Do not set a TTL on withdrawals** (`ttl_blocks` unset, the default), or set it far beyond any plausible stall. When it expires, the wallet cancels on refresh without asking the node. The TTL of a deposit comes from the sender's wallet.

### Epicmail and cancels

The relay sends a cancel to a wallet only when the wallet subscribed as protocol 3.1.0. epic-wallet 4.1.0 subscribes as 3.0.0 and has no handler for relay cancels, so moving to Epicmail does not change how its cancels behave. Epicmail accepts `protocol.cancel = true` (the default) for wallets that do not use it.

If the exchange wallet is ever replaced by a build that subscribes as 3.1.0, check what it does on receiving a cancel first. A relay cancel on a deposit is only safe when the wallet checks the chain before it acts on it. The trace log (`/var/log/epicmail/epicmail.log`) records the protocol version of each subscribing wallet. To switch relay cancels off, set `cancel = false` under `[protocol]` in `/etc/epicmail/epicmail.toml` and restart.

## 4. What improves with LEPIC and BT Wallet

[LEPIC](https://github.com/BTLabsUK/lepic) is a wallet engine for Epic Cash written in Rust. [BT Wallet](https://epiccash.btlabs.uk) is built on it. In LEPIC (per its source):

- A cancel of a transaction the other party can still complete looks the kernel up in the node's pool and on chain first. A hit refuses the cancel.
- After a cancel, the wallet keeps looking for the kernel. A late confirmation confirms the original entry and stores its outputs.
- An output that a scan restored in the meantime is merged back into the entry it belongs to, so there is no separate `Restore` entry.
- A cancel that arrives through the relay goes through the same checks.
- Epicmail passes cancels to wallets on protocol 3.1.0. It accepts the signed form `epicbox-cancel/1`, which only the participants of a transaction can produce. LEPIC speaks it.

Using LEPIC in an exchange is an integration project. The exchange's own accounting would still need to match deposits and withdrawals by kernel or output and not by slate id alone.

Docs: [LEPIC developer guide](https://docs.btlabs.uk/developers/lepic/), [LEPIC CLI reference](https://github.com/BTLabsUK/lepic/blob/main/docs/cli.md).

## 5. Links

- Epicmail repository: https://github.com/BTLabsUK/epicmail
- Latest release (binaries, `SHA256SUMS`, signature): https://github.com/BTLabsUK/epicmail/releases/latest
- Install script: https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh
- Release key, for checking by hand (`minisign`, key id `250522661E0CB33E`): `RWQ+swweZiIFJfbre/aOhYqQ1+82BHFnw8gF6ETbhCp5b7RB6RuMEVtP`. How to check a download: https://github.com/BTLabsUK/epicmail#run-a-relay
- Operating guide (install, limits, health endpoints, backup, logging, upgrade): https://github.com/BTLabsUK/epicmail/blob/main/docs/operating.md
- nginx example: https://github.com/BTLabsUK/epicmail/blob/main/packaging/nginx.example.conf
- Config example with every setting: https://github.com/BTLabsUK/epicmail/blob/main/packaging/epicmail.example.toml
- Cancel signature: https://github.com/BTLabsUK/epicmail/blob/main/docs/cancel-signature.md
- Deposit QR with address and memo (JavaScript, Python): https://github.com/BTLabsUK/epic-deposit-qr
- Status of BT Labs' own relay: https://status.btlabs.uk
- LEPIC: https://github.com/BTLabsUK/lepic, https://docs.btlabs.uk/developers/lepic/
- BT Wallet: https://epiccash.btlabs.uk
- Contact: the BT Labs Telegram group, https://t.me/BTLABS_EPIC. Issues: https://github.com/BTLabsUK/epicmail/issues
