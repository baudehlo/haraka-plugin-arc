# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.0.0] - 2026-11-10

- ARC sealing at data_post with mailauth 8.0.6: verifies SPF, DKIM, DMARC and an
  existing ARC chain on the message as received, then adds ARC-Seal,
  ARC-Message-Signature and ARC-Authentication-Results (i=N, cv=none/pass/fail).
- Seals relayed mail (`seal_relayed`) and mail whose transaction has
  `notes.arc_seal = true`; `notes.arc_seal = false` opts a message out.
- `notes.arc_original_sender`: the envelope sender before a rewrite such as SRS.
- Key from a file (`private_key`) or an environment variable (`private_key_env`,
  PEM or base64), selector from `selector` or `selector_env`.
- Never rejects mail: errors and timeouts leave the message unsealed.

[1.0.0]: https://github.com/baudehlo/haraka-plugin-arc/releases/tag/v1.0.0
