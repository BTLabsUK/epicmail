# Webhooks for the relay: research note

Status: research, no code. Date: 2026-11-13.

## Recommendation

Do not offer public webhooks. Offer one narrow, off-by-default feature for operators: a **wake hint** that the relay POSTs to an HTTPS URL on a host the operator has allowlisted in the config file, when a mailbox whose owner registered it has waiting mail. The audience is a merchant, exchange or service that runs its own wallet and wants to stop polling.

- The registration is signed by the mailbox key over (relay id, URL, expiry, nonce), and the target must echo a verification token before it receives anything.
- The callback carries no slate, no sender, no mailbox and no count: only an opaque subscription id. The receiver then drains through `/v1/pull` or mux/1, as today.
- Callbacks are signed with the Standard Webhooks scheme (HMAC-SHA256 over id, timestamp and body, per-subscription secret).
- Hints are level-triggered: "this subscription has waiting mail". Retries stop as soon as the mail is acked. At most one hint in flight per subscription, coalesced, rate-capped.
- Phones are a separate case. Their wake hint should go to a Web Push endpoint (UnifiedPush, or FCM through it) with an RFC 8291 encrypted body, as the design spec already leaves open under "Background delivery on phones". That is a second feature with its own decision.

The core needs only one thing from the event bus: a post-commit event `(mailbox, stored_at)` on a channel that a lagging consumer cannot block, plus a store query "which of these mailboxes have waiting mail" for reconciliation.

## Context from the design spec

The spec lists "push notifications" as not in the first version, and describes a "wake hint" as "(b) Later and opt-in": the relay calls a URL the wallet registered, with an empty body, when mail lands. It notes that this "is the only way to reach a suspended phone, and it needs a push gateway". Its privacy section requires "No address pairs and no IPs in logs or tables" and "Presence and delivery queries off unless a party to the message asks". Any webhook design has to stay inside those rules. A webhook table maps a mailbox to a URL, and a URL usually names its owner, so it is a new kind of record the relay keeps. That is acceptable for an operator's own merchant, who opts in knowingly. It is not acceptable as a default for ordinary users.

## 1. Threats

### SSRF

A webhook lets an outside party choose a URL that the relay's machine will call. The attacker aims it at internal services: localhost admin ports, the Postgres or metrics port in the scaled-out layout, the cloud metadata service. The Standard Webhooks spec calls webhooks "especially vulnerable to SSRF" ([spec](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)). The ways around a naive check:

- **Private and special ranges.** Loopback, RFC 1918, link-local (169.254.0.0/16, which holds the AWS/GCP/Azure metadata address 169.254.169.254), CGNAT 100.64.0.0/10, IPv6 loopback, ULA fc00::/7, link-local fe80::/10, and AWS's IPv6 metadata address fd00:ec2::254.
- **IPv6 forms of IPv4.** `::ffff:127.0.0.1` (IPv4-mapped), NAT64 `64:ff9b::/96`, 6to4 `2002::/16`. A check that only looks at IPv4 literals misses them.
- **DNS rebinding.** The name resolves to a public address at check time and a private one at connect time. OWASP states that checking DNS answers separately "does not prevent DNS rebinding" and that the connection must be bound to the validated address ([OWASP SSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)).
- **Redirects.** A public URL answers 302 to an internal one. OWASP says to disable redirects; Standard Webhooks treats 3xx as failure; the Matrix Web Push proposal says the same, because the redirect target escapes the check ([MSC4174](https://github.com/p1gp1g/matrix-spec-proposals/blob/webpush-pushkind/proposals/4174-webpush-pushkind.md)).
- **Proxy environment variables.** An HTTP client that honours `HTTPS_PROXY` sends traffic somewhere the check never saw.

OWASP's case 2 ("Application can send requests to ANY external IP address or domain name", which names webhooks) concludes that a block-list at the application layer is the best available there and should be backed by network isolation. Stripe and Svix add an egress proxy that does the resolve-and-block step, Stripe's [smokescreen](https://github.com/stripe/smokescreen), and run the senders in a subnet with no route to internal services ([Svix security](https://docs.svix.com/security)). An operator allowlist of hosts (OWASP case 1) is much stronger than any block-list, and it is what this note recommends.

### Mailbox enumeration and registration hijack

If anyone can register a hook for any mailbox, an attacker learns when any mailbox gets mail. A registration must be signed by the mailbox key. Responses to a registration must not depend on whether the mailbox has mail or has ever been used. The signed message must bind the relay id (so it cannot be replayed to another relay), the URL (so it cannot be redirected), an expiry and a nonce (so an old signature cannot revive a deleted hook). Deletion and renewal need the same signature.

### Timing and metadata leaks

- **Relay to receiver.** The receiver learns when mail arrived for the mailbox. For a merchant's own server this is the point. For a third-party receiver (a hosted webhook service, a push provider), it learns payment timing for that mailbox. A hint with an opaque subscription id and no body limits what it learns to "something arrived at this time".
- **Sender and receiver correlation.** An observer who sees the inbound post and the outbound callback a few milliseconds apart links the sender's IP to the receiver's host. The relay already sees both ends; a network observer does too. A small random delay (for example 0 to 2 s) and coalescing blur it. A full fix would need constant-rate cover traffic, which is out of scope.
- **Relay-side records.** The subscription table stores mailbox, URL and secret. Logs must hold neither, in line with the spec's privacy rule. Delivery metrics stay as totals.
- **DNS.** Each callback resolves the receiver's host, which tells the relay's resolver who receives mail and when. A long-lived connection pool and the allowlist reduce lookups.

### Abuse and amplification

- **One post, many callbacks.** If a mailbox may hold many hooks, one cheap PostSlate becomes many outbound requests. Cap hooks per mailbox (1 or 2) and per relay.
- **Post flooding.** A spammer posting to a merchant's mailbox makes the relay call the merchant repeatedly. Coalescing and a per-subscription rate cap (at most one hint per few seconds, a ceiling per hour) bound it to a constant.
- **Victim URLs.** The mailbox signature proves the mailbox owner consents, but says nothing about the URL owner. Without a check, anyone with a key pair can point the relay at a third party and use mail to that key as a trigger. UnifiedPush recommends validating a new push endpoint with a token round trip before use, to stop the push server being used "for Denial Of Service (DOS) amplification" ([UnifiedPush intro](https://unifiedpush.org/developers/intro/)). The relay should do the same: send a verification hint with a random token, and activate the hook only when the registrant returns the token through the relay.

### Authenticity, replay and TLS

- **Forged callbacks.** Anyone can POST to the receiver's URL. The receiver needs a signature it can check. GitHub, Stripe and Svix all sign with HMAC-SHA256 and a per-endpoint secret ([GitHub](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries), [Svix](https://docs.svix.com/receiving/verifying-payloads/how-manual)).
- **Replay.** A captured callback replayed later. The signed content must include a timestamp; Stripe's libraries reject anything more than 5 minutes off, and Stripe re-signs with a fresh timestamp on every retry ([Stripe](https://docs.stripe.com/webhooks)). The message id lets the receiver deduplicate ([GitHub best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)). For a hint that only says "go and pull", a replay causes one extra pull, so the harm is small.
- **TLS.** HTTPS only, certificates validated against the system or webpki roots, no per-hook option to turn validation off. GitHub verifies certificates by default and recommends keeping it on.

### Retry storms and slow receivers

- A receiver that is down while mail keeps arriving must not build a queue of callbacks. With level-triggered hints there is at most one pending hint per subscription.
- A receiver that accepts the connection and then trickles bytes (slowloris) ties up a sender task. Set a connect timeout, a total request timeout, and a cap on response bytes read. GitHub gives receivers 10 s; Standard Webhooks suggests 15 to 30 s for receivers that process work. A hint needs no processing, so 10 s total is enough.
- Bound the number of concurrent outbound requests per relay and per target host, so a few slow hosts cannot starve the rest.

## 2. Patterns used in practice

| Pattern | Source | Use here |
| --- | --- | --- |
| Sign `id.timestamp.body` with HMAC-SHA256; headers `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64>`; secret 24 to 64 random bytes shown as `whsec_…`; space-separated list for rotation | [Standard Webhooks 1.0.0](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) | Yes, as is. Receivers can use existing Standard Webhooks libraries. |
| Asymmetric `v1a` (ed25519) signatures | Same spec, which prefers asymmetric when the producer does not control both ends | Optional later: one relay key in the info document. |
| Timestamp tolerance 5 minutes; new signature per retry | [Stripe](https://docs.stripe.com/webhooks), [Svix](https://www.svix.com/resources/webhook-best-practices/security/) | Yes. |
| Thin payloads: ids only, the consumer fetches the rest | Standard Webhooks "thin vs full"; Matrix `event_id_only` pushers ([Matrix push gateway API](https://spec.matrix.org/latest/push-gateway-api/)) | Thinner still: an opaque subscription id. |
| Reject `http://` at registration | [Svix](https://www.svix.com/resources/webhook-best-practices/security/) | Yes. |
| Egress proxy that resolves, blocks private ranges and pins the address; workers in an isolated subnet | [smokescreen](https://github.com/stripe/smokescreen), [Svix](https://docs.svix.com/security), [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | The same checks inside the relay's HTTP client, plus the host allowlist. An operator may add a proxy. |
| No redirects; 3xx counts as failure; 410 disables the endpoint; honour 429 and `Retry-After` | Standard Webhooks | Yes. |
| Retries with exponential backoff and jitter over days, then disable and tell the owner | Standard Webhooks (schedule up to about 75 h), Stripe (up to 3 days) | Shorter, because hints are level-triggered: retry while mail is waiting; disable after 3 days of failure. |
| Verify a new endpoint with a token round trip; reject non-global addresses on every send | [UnifiedPush](https://unifiedpush.org/developers/intro/) | Yes. |
| Static source IPs for receivers' firewalls; not a substitute for signatures | Standard Webhooks, [Svix](https://docs.svix.com/security) | Document the relay's egress IP; receivers still check signatures. |

## 3. Alternatives

| Option | Who it serves | Privacy | Operator burden |
| --- | --- | --- | --- |
| **mux/1 socket** (in the design) | Desktop, foreground phones, servers that can hold a socket | Nothing leaves the relay except to the owner | None beyond what is built |
| **`/v1/pull` long-poll, up to 25 s** (in the design) | Servers behind firewalls that block websockets; phone background fetch | Same as above | None beyond what is built |
| **Operator webhook (wake hint)** | Servers that cannot hold a connection: serverless functions, PHP shops, systems that only take inbound HTTP | Receiver learns arrival times; relay stores mailbox to URL | Outbound HTTP client, SSRF controls, retry state, allowlist upkeep |
| **Web Push to UnifiedPush / FCM** | Suspended phones | Push server and, through FCM or APNs, Google or Apple learn arrival times for an endpoint; body encrypted with RFC 8291 ([UnifiedPush](https://unifiedpush.org/developers/intro/)) | VAPID key (RFC 8292), endpoint validation, the same SSRF controls; plus app work for a distributor |
| **ntfy topic** as receiver | Self-hosters | The topic name is the credential ("the topic is essentially a password", [ntfy docs](https://docs.ntfy.sh/publish/)) | ntfy accepts plain POSTs, so it is one more allowlisted host |

A server that can hold one outbound connection is better served by mux/1 or `/v1/pull`: no new state at the relay, no new leak, no outbound requests. Webhooks only add value for receivers that cannot. Phones need Web Push, which shares the outbound machinery (signing aside) but is a separate decision.

## 4. Minimal safe design

Everything below is off unless the operator config enables it and lists allowed hosts.

### Operator config

```toml
[webhooks]
enabled = false
allowed_hosts = ["hooks.example-shop.com"]   # exact host match; port 443 only
max_hooks_per_mailbox = 1
max_hooks_total = 1000
min_interval_secs = 5        # per subscription
max_hints_per_hour = 120     # per subscription
max_expiry_days = 30
timeout_connect_secs = 3
timeout_total_secs = 10
max_concurrent = 32          # whole relay
max_concurrent_per_host = 4
jitter_max_ms = 2000
```

A config-only mode (operator writes `mailbox = url` pairs and the secret into the file) covers a relay run by the merchant itself and needs no wire messages. The signed registration below is for a merchant using someone else's relay whose operator allows the merchant's host.

### Registration (mux/1 frame or `POST /v1/hooks`)

```json
{
  "type": "HookRegister",
  "mailbox": "<secp256k1 public key, as used for Subscribe>",
  "relay": "<relay id from the info document: domain:port>",
  "url": "https://hooks.example-shop.com/epicbox",
  "expires": 1765000000,
  "nonce": "<16 random bytes, base64url>",
  "signature": "<mailbox signature over the canonical string below>"
}
```

Signed string, newline-separated, fixed order: `epicbox-hook/1`, relay, mailbox, url, expires, nonce. Use the same signature scheme the relay already verifies for Subscribe, so no new crypto enters the core.

Relay checks, in order: feature on; `relay` equals its own id; `expires` in the future and within `max_expiry_days`; nonce not seen for this mailbox (keep nonces until their expiry); URL parses, scheme `https`, no userinfo, port 443, host in `allowed_hosts`; signature valid; per-mailbox and total caps. Any failure returns one generic error. The relay never says whether the mailbox has mail.

On success the relay creates the subscription in state `pending` and returns, over TLS:

```json
{ "type": "HookPending", "sub": "sub_<16 random bytes>", "secret": "whsec_<32 random bytes, base64>" }
```

It then sends one `epicbox.hook.verify` callback (format below) whose `data` carries a 32-byte `token`. The registrant sends `HookConfirm {sub, token}` through the relay within 10 minutes; only then does the state become `active`. This proves the URL owner and the mailbox owner cooperate.

`HookDelete` and renewal reuse `HookRegister` (signed, new nonce). A renewal with the same URL keeps the `sub` and secret. A new URL starts over.

### Callback

```
POST /epicbox HTTP/1.1
Host: hooks.example-shop.com
Content-Type: application/json
User-Agent: epicmail
webhook-id: evt_<random, unique per hint>
webhook-timestamp: 1763040000
webhook-signature: v1,<base64 HMAC-SHA256(secret, id + "." + timestamp + "." + body)>

{"type":"epicbox.mail.waiting","timestamp":"2026-11-13T12:00:00Z","data":{"sub":"sub_..."}}
```

No mailbox, sender, slate, message id or count. The receiver maps `sub` to the mailbox it registered, then drains with `/v1/pull` or mux/1. On a retry the id stays and the timestamp and signature are new, as in Stripe and Standard Webhooks.

### Delivery rules

- **Client.** HTTPS only, certificate validation always on, redirects off, system proxy variables ignored. A custom DNS resolver resolves the host and drops every non-global address (the ranges in section 1, with IPv4-mapped and NAT64 forms unwrapped), and the connection goes to an address that passed. Checking inside the resolver used for the connection is what stops rebinding. In Rust the std `IpAddr::is_global` has been unstable, so the block list is explicit code with tests.
- **Level-triggered.** A subscription has a flag "hint due". The bus event sets it. The sender clears it when a 2xx arrives. Before each retry the sender asks the store whether the mailbox still has waiting mail; if not, it drops the retry.
- **Coalescing.** One request in flight per subscription; at least `min_interval_secs` between hints; random delay up to `jitter_max_ms`.
- **Status handling.** 2xx: done. 3xx and other 4xx: failure. 410: disable at once. 429 and 503: honour `Retry-After`, capped.
- **Backoff.** 5 s, 30 s, 2 min, 10 min, 1 h, then hourly while mail is waiting. Three days without a 2xx: state `disabled`. The owner sees it on the next pull or Attached as a flag on the subscription, since the relay has no other channel to the owner.
- **Expiry.** Subscriptions past `expires` are deleted, along with their secret.
- **Logs and metrics.** No mailbox, URL or host in logs. Metrics are totals: hints sent, failures by class, disabled count.

### What the event bus must give the core

1. A post-commit event `MailStored { mailbox, stored_at }`, emitted after the store commit and never before, the same event that feeds WebSocket push and mux/1.
2. A channel where a slow consumer cannot block the producer: a broadcast with lag detection. When the hook dispatcher lags, it treats the gap as "anything may have arrived" and reconciles.
3. A store query `mailboxes_with_waiting_mail(set) -> set`, used for reconciliation after lag or restart, and before each retry.
4. Hook state behind the same store interface as messages (`hooks` table: sub, mailbox, url, secret, expires, state, last_ok, fail_since), so the Postgres layout gets it with no extra work. Pending hint flags can live in memory; after a restart the dispatcher runs one reconciliation pass over active subscriptions.
5. A separate tokio task (or pool) for outbound HTTP with its own concurrency limits, so a slow receiver never touches the socket-serving path.

### What to decide before building

- Whether any merchant or exchange has asked for this. If not, mux/1 and `/v1/pull` cover servers, and the work can wait.
- Whether phone wake hints through Web Push are wanted (the spec's open question). If yes, build the outbound client, SSRF checks and level-triggered dispatcher once and use them for both.
