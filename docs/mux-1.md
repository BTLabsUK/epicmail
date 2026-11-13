# mux/1: one socket, many mailboxes

Status: **draft 1**. Wire changes need agreement from the relay and the LEPIC client side.

mux/1 is an optional extension to the Epicbox 3.0.0 websocket protocol. One socket carries any number of proven mailboxes. The relay pushes each message as soon as it is stored. The client acknowledges messages without signatures. A token lets a client resume a session after a reconnect without signing again.

A client that does not ask for mux/1 sees plain 3.0.0. A relay that does not offer it answers the request with a plain `Ok`, and the client carries on with 3.0.0.

## 1. Conventions

- Frames are JSON text frames, one object per frame, with a `type` field. As in 3.0.0, the relay matches `type` without regard to case. It always sends the exact spelling shown here.
- `mailbox` is the bare 52-character base58check public key. In Attach a client may send a full address (`epicbox://key@domain:port`). The relay keeps only the key, and every reply names the bare key.
- `id` is the relay's message id, the same value as `epicboxmsgid` in 3.0.0. It is an opaque string of at most 64 characters.
- `ref` is optional on every client frame. It is a string of at most 64 characters. The relay copies it into the `Ok`, `Error` or `Attached` that answers that frame. Pushed frames (`Mail`, `Detached`) carry no `ref`.
- Unknown fields are ignored on both sides. Unknown frame types from the client get `Error` with `code: "unknown_type"`. The socket stays open.
- Liveness uses websocket ping frames. The relay pings every 30 s and closes a socket after 90 s without a pong. The client may ping too, and the relay answers. The relay sends no periodic `Challenge` to a mux/1 socket.

### Errors

```json
{"type":"Error","kind":"InvalidRequest","code":"too_many_mailboxes","description":"...","ref":"7"}
```

`kind` is one of the 3.0.0 kinds (`UnknownError`, `InvalidRequest`, `InvalidSignature`, `InvalidChallenge`, `TooManySubscriptions`), so an old parser still reads it. `code` is the exact reason, and mux/1 clients should branch on `code`:

| code | kind | when |
|---|---|---|
| `bad_frame` | InvalidRequest | missing or wrong-typed field, frame over the size limit |
| `unknown_type` | InvalidRequest | frame type not known in this mode |
| `not_mux` | InvalidRequest | mux/1 frame on a socket that did not negotiate it |
| `classic_only` | InvalidRequest | `Subscribe`, `Made` or `Unsubscribe` on a mux/1 socket |
| `bad_address` | InvalidRequest | address does not parse or its key is invalid |
| `bad_signature` | InvalidSignature | signature does not verify over the socket challenge |
| `too_many_mailboxes` | TooManySubscriptions | over 64 in one Attach, or over 256 on the socket |
| `token_unknown` | InvalidChallenge | resume token not known, used already, or expired |
| `not_attached` | InvalidRequest | Hold names a message of a mailbox not attached here |
| `unknown_id` | InvalidRequest | Hold names an id that is not in flight on this socket |
| `rate_limited` | InvalidRequest | a limit was hit; `retry_after` (seconds) is set |
| `post_refused` | InvalidRequest | PostSlate refused; `description` says why |
| `internal` | UnknownError | store error; the frame had no effect and can be retried |

## 2. Negotiation

The client sends `ClientDetails` as in 3.0.0, with one extra field:

```json
{"type":"ClientDetails","wallet_version":"...","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]}
```

A relay that offers mux/1 answers:

```json
{"type":"Ok","ext":["mux/1"],"challenge":"b3JkKQ1y0f5C3cS0nVb1zw","limits":{"attach_per_frame":64,"mailboxes_per_socket":256,"inflight_per_socket":32,"hold_max_s":3600}}
```

- `challenge` is fresh for this socket: 16 random bytes in base64url without padding. It is never sent again and never reused. Attach signatures are over this string. It replaces the first `Challenge` frame, which may be the fixed constant in compatible mode, so mux/1 signatures cannot be replayed on another socket.
- From this `Ok` on, the socket is in mux/1 mode. The relay sends no `Challenge` or `Slate` frames on it.
- If the relay does not offer mux/1, it answers a plain `{"type":"Ok"}` and the socket stays 3.0.0.
- `ClientDetails` must come before any `Subscribe`. If it comes after one, the relay answers plain `Ok` and the socket stays 3.0.0.
- The relay may already have sent its first `Challenge` when the socket opened. A mux/1 client ignores it.
- `GetVersion` still answers `3.0.0`.

## 3. Client frames

### Attach

```json
{"type":"Attach","ref":"1","mailboxes":[{"address":"<key or full address>","signature":"<DER hex>"}]}
```

Each `signature` is the mailbox key's signature over the socket `challenge` (SHA-256 of the UTF-8 bytes, secp256k1 ECDSA, DER hex). This is the same rule as a 3.0.0 Subscribe. Up to 64 entries per frame and up to 256 mailboxes per socket in total.

The relay checks every entry and answers once:

```json
{"type":"Attached","ref":"1",
 "mailboxes":[{"mailbox":"<key>","ok":true,"waiting":3},
              {"mailbox":"<key>","ok":false,"code":"bad_signature"}],
 "token":"<base64url 32 bytes>","token_expires":1794614400}
```

- `waiting` is the number of messages stored for the mailbox when it was attached. Those messages follow as `Mail`.
- An entry that fails does not fail the frame. When every entry fails, the relay still answers `Attached` with all `ok: false`. The token is then left unchanged and is omitted if none exists yet.
- Attaching a mailbox that is already attached on this socket succeeds and does nothing.
- **Newest socket wins.** A mailbox is pushed to one socket only: the one that attached or subscribed it last.
  - An older mux/1 socket that held it gets `Detached` with `reason: "replaced"`, and its in-flight messages for that mailbox are offered again on the new socket.
  - An older 3.0.0 socket stays open and can still collect with its own Subscribe, but gets no pushes. The relay closes the oldest 3.0.0 sockets of an address only beyond a cap (default 4 live sockets per address). Closing on every new Subscribe would make two processes of one wallet reconnect against each other without end.
  - A client must not re-attach automatically after `replaced`. Two app instances doing so would take the mailbox from each other in a loop.
- Every `Attached` that has at least one `ok: true` carries a new token. The old token stops working.

### Detach

```json
{"type":"Detach","ref":"2","mailboxes":["<key>"]}
```

Answer: `{"type":"Ok","ref":"2"}`. Messages in flight for that mailbox go back to waiting. Detaching a mailbox that is not attached is not an error.

### Resume

```json
{"type":"Resume","ref":"3","token":"<token>"}
```

Sent instead of Attach on a new socket, after negotiation. On success the relay attaches the session's mailbox set again, without signatures, and answers `Attached` with a new token. The set is the one held when the token was issued, as changed since by Attach and Detach. The old token is spent.

On failure the answer is `Error` with `code: "token_unknown"`. The client then attaches with signatures. Tokens:

- 32 random bytes, base64url. Single use. Valid 24 h from issue (`token_expires` is unix seconds).
- The relay holds only a SHA-256 hash of each token, in memory. A relay restart forgets all tokens, so the next Resume gets `token_unknown`.
- One live token per session. A Resume or Attach that issues a new token ends the old one. If two sockets race with the same token, the first wins and the second gets `token_unknown`.
- A resumed mailbox follows the newest-socket-wins rule like an Attach.

### Ack

```json
{"type":"Ack","ref":"4","ids":["<id>","<id>"]}
```

Up to 256 ids. No signature: the socket has already proven the mailboxes. The relay marks each message made and deletes its payload in one commit, then answers `{"type":"Ok","ref":"4"}`. Ids that are unknown, already acked, or belong to a mailbox not attached here are ignored, so Ack can be retried safely. The Ok means the acks are stored.

### Hold

```json
{"type":"Hold","ref":"5","id":"<id>","seconds":120}
```

The client cannot handle this message yet. The relay stops offering it for `seconds` (1 to 3600; larger values are clamped) and goes on with the mailbox's next message. After the hold it is offered again. Answer: `Ok`. The message keeps its 7-day expiry.

### PostSlate

The 3.0.0 `PostSlate` frame, unchanged, with an optional `ref`:

```json
{"type":"PostSlate","ref":"6","from":"...","to":"...","str":"...","signature":"..."}
```

The relay answers `{"type":"Ok","ref":"6"}` after the message is committed, or after it is committed to the forward queue for another domain. A refused post gets `Error` with `code: "post_refused"` or `rate_limited`. The 3.1.0 cancel fields are not part of mux/1.

### Not allowed on a mux/1 socket

`Subscribe`, `Made`, `Unsubscribe` and `Challenge` get `Error` with `code: "classic_only"`. `GetVersion` and `ClientDetails` are answered as in 3.0.0.

## 4. Relay frames

### Mail

```json
{"type":"Mail","mailbox":"<key>","id":"<id>","from":"<sender address>","str":"<slate json string>","signature":"<sender sig over str>","created":1794528000}
```

`from`, `str` and `signature` are exactly what the sender posted, the same fields as in a 3.0.0 `Slate`. The client checks the sender signature as it does today.

Delivery rules:

- A message is pushed right after it is committed, or when its mailbox is attached or resumed.
- At most 32 messages are in flight (pushed, not acked or held) per socket. A slot opens when the client acks or holds one.
- Within one mailbox, messages are offered oldest first. A held message steps aside.
- A message in flight is not pushed again on the same socket. It is offered again when the socket closes, the mailbox is detached or moved to another socket, or its hold ends.
- So a message can arrive more than once across sockets. Clients deduplicate by `id`, as they do today.
- Mail that has expired (7 days after it was stored) is never pushed.

### Detached

```json
{"type":"Detached","mailbox":"<key>","reason":"replaced"}
```

The relay stopped delivering this mailbox on this socket. Reasons: `replaced` (attached or subscribed on another socket), `limit` (operator limit lowered), `shutdown` (relay draining). The client may attach it again, which will in turn replace the other socket.

### Shutdown

On SIGTERM the relay closes every socket with code 1001. Clients reconnect, to another instance if there is one, and Resume. Tokens do not survive a restart.

## 5. Limits

The relay publishes these limits in the `Ok` and in its info document (`/.well-known/epicbox.json`, `features.mux/1`):

| limit | default |
|---|---|
| mailboxes per Attach | 64 |
| mailboxes per socket | 256 |
| in-flight Mail per socket | 32 |
| ids per Ack | 256 |
| hold | 1 to 3600 s |
| Attach and Resume frames per socket | 30 per minute |
| failed signatures per IP prefix | 120 per minute, then `rate_limited` |
| mux/1 sockets per IP prefix | operator setting, default 64 |

## 6. Privacy

- The relay operator sees which mailboxes share a socket, and so belong to one wallet. 3.0.0 leaks the same by timing and IP, but less directly. Clients that care can split mailboxes over several sockets, for example one per mailbox group when Tor is on.
- A stolen token lets its holder receive and ack the session's mail for at most 24 h, or until the owner resumes or attaches again, which spends it. Payloads stay encrypted to the recipient key. The token travels only inside TLS.
- The relay keeps no token, session or mailbox set on disk. Logs carry no mailbox keys, tokens or payloads.
- Push timing tells an observer of the socket when mail arrives. This is no different from a 3.0.0 listener.

## 7. Example

```
C: {"type":"ClientDetails","wallet_version":"5.0.0","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]}
R: {"type":"Ok","ext":["mux/1"],"challenge":"Zx3...","limits":{...}}
C: {"type":"Attach","ref":"a1","mailboxes":[{"address":"es5d...","signature":"3044..."},{"address":"eQ2k...","signature":"3045..."}]}
R: {"type":"Attached","ref":"a1","mailboxes":[{"mailbox":"es5d...","ok":true,"waiting":1},{"mailbox":"eQ2k...","ok":true,"waiting":0}],"token":"q9...","token_expires":1794614400}
R: {"type":"Mail","mailbox":"es5d...","id":"m-17","from":"eQ2k...@epicbox.example","str":"{...}","signature":"3044...","created":1794527000}
C: {"type":"Ack","ref":"k1","ids":["m-17"]}
R: {"type":"Ok","ref":"k1"}
   ... socket drops ...
C: {"type":"ClientDetails",...,"ext":["mux/1"]}
R: {"type":"Ok","ext":["mux/1"],"challenge":"P0a...",...}
C: {"type":"Resume","ref":"r1","token":"q9..."}
R: {"type":"Attached","ref":"r1","mailboxes":[...],"token":"Hk...","token_expires":...}
```

## 8. Open points

1. Newest-wins for push with a cap on old 3.0.0 sockets (section 3) instead of closing older sockets at once. The app's resume drain then never forces the listener to reconnect, but while it is subscribed it receives the pushes for the payments address, not the listener.
2. The token lifetime is fixed at 24 h. A shorter value only matters for phones that sleep longer and then fall back to signatures.
3. 3.1.0 cancel over mux/1 is left out until cancel is agreed for 3.0.0 relays.
