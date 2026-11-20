# Changelog

Net changes per release. Configuration keys are in `packaging/epicmail.example.toml`; every
release reads the data of every earlier one.

## 0.1.13

Forwarding:
- A peer relay's temporary answers keep a forwarded slate queued and retried: Busy, a rate
  limit, a full mailbox or store, too many waiting messages from one sender, and an internal
  error. Before, all but Busy and the rate limit dropped the slate after three attempts.
- A CancelTx forwarded to a relay that does not answer it (the stock Node relay) is dropped
  after one attempt and no longer holds back slates queued for that relay.
- A forward tries each public address of the peer in turn, not only the first.
- A post the federation `allow` or `deny` list refuses is counted as `result="policy"` and
  logged at warn, naming the peer. The answer to the wallet is unchanged.
- `federation.allow` and `federation.deny` entries must be a host name with an optional
  port; the relay refuses to start on anything else. A non-empty `allow` is reported at
  startup and by `check-config`.
- A post for a destination with port 0 is refused.
- New metrics `epicbox_forwards_dropped_total` (by peer and reason),
  `epicbox_forwards_expired_total` and `epicbox_sig_failure_closes_total`.

Signatures and limits:
- A socket is closed with code 4003 after 8 failed signatures. A subscribed wallet's
  challenge-round Subscribe and Made, and a socket's first signed frame, are no longer
  refused because other clients in its prefix sent bad signatures.
- `/v1` accepts a proof signed for any of the relay's names (`server.domain` or an alias).
- A PostSlate without `str` or `signature` no longer counts as a failed signature.

Delivery:
- With `protocol.cancel = false`, GetVersion answers 3.0.0 and a Made marked 3.1.0 is
  served as 3.0.0. Before, such a Made got no answer and the slate was delivered again.
- A message in flight is handed back at once when a mux/1 mailbox moves to another socket
  or a classic socket switches keys, instead of after its 60 s lease.
- Fixes to classic Made and pending cancel acknowledgements on sockets that change keys,
  and to mux/1 Ack with held messages.

Operations:
- `tools/install.sh` keeps the replaced binary as `epicmail.prev` for a rollback and handles
  a config without a `listen` line.
- One warning per process when X-Forwarded-For arrives from a peer not in
  `server.trusted_proxies`.
- Docs: the `allow` list, `shared_sources` behind the onion nginx setup, `log.file.keep`.

## 0.1.12

- mux/1 Attach signatures can be bound to the relay's host: `epicbox-attach/1:<host>:<challenge>`,
  with `host` the relay's domain or an alias. The bare form stays accepted
  (`protocol.accept_bare_attach`, default true). An Attach signed for another host is answered
  `wrong_host` and is not counted as a failed signature.
- `protocol.accept_bare_cancel` (default true): false accepts only CancelTx signed as
  `epicbox-cancel/1:<txid>`.
