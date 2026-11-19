# Signing a cancel: `epicbox-cancel/1`

For wallet developers. This says what to sign for an Epicbox `CancelTx`, how a relay advertises
that it takes the new form, and what to do against a relay that does not.

## The problem

Epicbox 3.1.0 wallets sign `CancelTx` over the bare transaction id: the 32 lowercase hex
characters of `epicboxtxid`. That is the same text, signed by the same key, as `epicboxtxidsig` in
the `PostSlate` that carried the slate. A relay that stored the `PostSlate`, and any relay it was
forwarded to, can replay `epicboxtxidsig` as a cancel.

## The new form

Sign this text instead:

```
epicbox-cancel/1:<epicboxtxid>
```

- `<epicboxtxid>` is the txid as sent in `PostSlate` (32 lowercase hex characters, no dashes).
- The prefix is `epicbox-cancel/1:` (ASCII, a colon, no space, no trailing newline).
- Everything else is as for every Epicbox signature: ECDSA over the SHA-256 of the UTF-8 text, DER
  encoded, hex in the `signature` field, made with the key of the `address` field. The frame is
  unchanged:

```json
{"type":"CancelTx","address":"<key or address>","epicboxtxid":"<32 chars>","signature":"<DER hex>"}
```

A signature over the bare txid does not verify over the prefixed text and the other way round, so
a copy of `epicboxtxidsig` is not a valid new-form cancel.

## How a relay advertises it

In band, on the connection you cancel on. Offer the token in `ClientDetails`:

```json
{"type":"ClientDetails","wallet_version":"...","wallet_mode":"send","protocol_version":"3.0.0","ext":["epicbox-cancel/1"]}
```

A relay that verifies the new form repeats the token in the answer to that frame:

```json
{"type":"Ok","ext":["epicbox-cancel/1"]}
```

On a mux/1 socket, list it next to the other extensions
(`"ext":["mux/1","txcancel/1","epicbox-cancel/1"]`) and read the relay's `Ok`, whose `ext` holds the
ones it accepted.

The relay also lists the feature in `GET /.well-known/epicbox.json`, with the text it verifies:

```json
"features": {"epicbox-cancel/1": {"signed_text": "epicbox-cancel/1:<txid>"}}
```

Reading the file is optional. The `Ok` echo on the connection you cancel on is the signal to use.

## Fallback

- The `Ok` has no `ext`, or no `epicbox-cancel/1` in it (a 3.1.0 relay without the form, a 3.0.0
  relay, any relay that ignores `ext`): sign the bare txid, as before.
- Do not retry the other form after an error. A relay that echoed the token verifies both forms,
  so a bare cancel to it also works; a relay that did not echo it verifies only the bare one.

## What the relay does

Epicmail (0.1.9 and later) verifies the prefixed form first and the bare form second, on a classic
socket, on mux/1 `txcancel/1`, and on a cancel forwarded from another relay. It forwards the
signature unchanged with `cancelrequestid`, so a peer that has the form verifies it. Stock 3.1.0
wallets keep working because the bare form is still accepted. Setting
`protocol.accept_bare_cancel = false` (it defaults to true) drops it: the relay then cancels only
on the prefixed form and refuses a bare one with `InvalidSignature`, and
`/.well-known/epicbox.json` says `"bare_accepted": false` for the feature. Turn it off only once
the wallets that use this relay send the prefixed form.
