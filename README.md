# haraka-plugin-arc

ARC (Authenticated Received Chain, [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) sealing for [Haraka](https://haraka.github.io).

When a server forwards mail, SPF breaks and DKIM may break, so the next receiver can no longer see that the message was authentic when it arrived. ARC fixes that: the forwarder records the SPF, DKIM, DMARC and ARC results it saw in an `ARC-Authentication-Results` header and signs it, together with the message, under its own domain (`ARC-Message-Signature`, `ARC-Seal`). A receiver that trusts the forwarder, such as Gmail for a forwarder with a good reputation, can then use those results when SPF or DKIM fails at its own end.

This plugin adds that ARC set to mail that Haraka relays or forwards. It uses [mailauth](https://github.com/postalsys/mailauth) for the verification and the signatures.

## Install

```sh
npm install haraka-plugin-arc
```

Add `arc` to `config/plugins`: **after** every plugin that rewrites the envelope sender or recipient (for example an SRS or alias plugin), and **before** your queue plugin or outbound. The plugin works in the `data_post` hook.

```
# config/plugins
...
aliases
arc
queue/smtp_forward
```

Requires Node.js 20.18.1 or later (mailauth's minimum) and Haraka 3.

## Configuration: `config/arc.ini`

```ini
[main]
enabled=true
domain=example.net
selector=arc2026
private_key=arc/private.pem
;authserv_id=mx.example.net
seal_relayed=true
add_authentication_results=false
```

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false`: the plugin loads but never seals. |
| `domain` | (none) | The signing domain, `d=` of the ARC-Seal and ARC-Message-Signature. |
| `selector` | (none) | The DNS selector, `s=`. |
| `selector_env` | (none) | The name of an environment variable that holds the selector. Wins over `selector` when the variable is set. |
| `private_key` | (none) | A PEM file with the private key, relative to Haraka's config directory or absolute. RSA (at least 1024 bits, 2048 recommended) or Ed25519. |
| `private_key_env` | (none) | The name of an environment variable that holds the private key, as PEM or as the base64 of the PEM. Wins over `private_key` when the variable is set. For containers that inject secrets through the environment. |
| `authserv_id` | `config/me` | The authserv-id in the ARC-Authentication-Results header: your server's host name. |
| `seal_relayed` | `true` | Seal mail that Haraka relays (`connection.relaying`). Set it to `false` if your relaying is only for your own users' outgoing mail, and let the forwarding plugin ask for a seal (below). |
| `add_authentication_results` | `false` | Also add the `Authentication-Results` header with the same results, under the ARC set. |

The signing algorithm follows the key: `rsa-sha256` for an RSA key, `ed25519-sha256` for an Ed25519 key.

The key is loaded and checked when Haraka starts (and when `arc.ini` changes). Without a domain, a selector or a usable key, the plugin logs one error, for example `sealing disabled: no private key`, and seals nothing. It never logs the key.

The plugin times out one second before Haraka's plugin timeout (`config/arc.timeout`, else `config/plugin_timeout`, default 30 seconds).

## Which messages are sealed

1. A plugin set `connection.transaction.notes.arc_seal = true`: always sealed.
2. `notes.arc_seal = false`: never sealed.
3. Otherwise: sealed when `seal_relayed=true` and the connection is relaying.

Ordinary inbound mail that Haraka delivers locally is never sealed.

A message that already has an ARC chain gets the next instance (`i=2`, ...) with `cv=pass` when the chain verifies and `cv=fail` when it does not. A chain whose newest seal already says `cv=fail` is not sealed again (RFC 8617 section 5.1).

## Never rejects mail

ARC is information for the next receiver, not a filter. When verification or sealing fails (a DNS timeout, a broken key, a parser error, a chain that cannot be extended), the plugin logs the reason and calls `next()`: the message goes on unsealed.

The plugin reads the message as a stream, so memory use does not grow with the message size and there is no size limit.

## The notes API (for other plugins)

| Note | Type | Meaning |
|---|---|---|
| `transaction.notes.arc_seal` | `boolean` | `true`: seal this message. `false`: do not. |
| `transaction.notes.arc_original_sender` | `string` | The envelope sender as it arrived, before your plugin rewrote `transaction.mail_from` (for example with SRS). SPF is checked for this address. `''` is the null sender. Without it, the plugin uses `transaction.mail_from`. |

SPF is checked with the connection's remote IP and HELO name.

## Results

The plugin stores its outcome in Haraka's result store, `transaction.results.get('arc')`:

- `pass: ['sealed']`, with `instance` (the new `i=`) and `cv`;
- `skip: [reason]`: the message was not sealed, for example `ARC chain fail (...)`;
- `err: [message]`: verification or sealing failed, for example `timed out after 29s`.

The log has one line per sealed message, for example
`sealed i=1 cv=none d=example.net (spf=pass dkim=pass dmarc=pass arc=none)`.

## DNS

The ARC public key is published like a DKIM key, as a TXT record at `<selector>._domainkey.<domain>`. If you already sign with DKIM for that domain, you can use the same key and selector for ARC: no new DNS record is needed.

```
arc2026._domainkey.example.net. TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."
```

## Example: a forwarding plugin

A plugin that forwards `info@example.net` to an outside mailbox, rewrites the envelope sender with SRS, and asks for an ARC seal:

```js
// plugins/forward_info.js
const constants = require('haraka-constants')

exports.hook_rcpt = function (next, connection, params) {
  const txn = connection.transaction
  const rcpt = params[0]
  if (rcpt.address.toLowerCase() !== 'info@example.net') return next()

  // Record the sender before the SRS rewrite: ARC reports SPF for it.
  txn.notes.arc_original_sender = txn.mail_from.address
  txn.notes.arc_seal = true

  rcpt.user = 'owner'
  rcpt.host = 'gmail.com'
  txn.mail_from = srsRewrite(txn.mail_from) // your SRS code
  connection.relaying = true
  next(constants.ok)
}
```

```
# config/plugins
forward_info
arc
```

```ini
# config/arc.ini
[main]
domain=example.net
selector=mail
private_key=dkim/example.net/private
seal_relayed=false
```

To check the result, forward a message to a Gmail address and open "Show original": the `ARC-Seal` from `d=example.net` is at the top, and Gmail's `Authentication-Results` says `arc=pass`.

## Development

```sh
npm ci
npm run lint
npm test
```

The tests use `node:test`, generate their keys and answer DNS from a table: they need no network.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Matt Sergeant.
