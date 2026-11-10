'use strict'

// ARC (RFC 8617) sealing for Haraka. mailauth verifies the message as it
// arrived (SPF, DKIM, DMARC, an existing ARC chain) and builds the new ARC set.

const crypto = require('node:crypto')
const dns = require('node:dns')
const { PassThrough } = require('node:stream')

const mailauth = require('mailauth')

// Top to bottom, as they must appear in the message.
const ARC_HEADERS = ['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results']

// mailauth seals with RSA keys from 1024 bits; receivers ignore shorter ones (RFC 8301).
const MIN_RSA_BITS = 1024

exports.register = function () {
  this.load_arc_ini()
}

exports.load_arc_ini = function () {
  this.cfg = this.config.get(
    'arc.ini',
    { booleans: ['+main.enabled', '+main.seal_relayed', '-main.add_authentication_results'] },
    () => this.load_arc_ini(),
  )
  this.authserv_id =
    setting(this.cfg.main.authserv_id) || setting(this.config.get('me')) || undefined
  this.seal = this.load_seal_options()
}

// { signingDomain, selector, privateKey } for mailauth, or null (sealing off, logged once).
exports.load_seal_options = function () {
  const main = this.cfg.main
  if (!main.enabled) {
    this.loginfo('disabled in arc.ini')
    return null
  }
  const off = (reason) => {
    this.logerror(`sealing disabled: ${reason}`)
    return null
  }

  const domain = setting(main.domain)
  if (!domain) return off('no domain in arc.ini')
  const selector = from_env(main.selector_env) || setting(main.selector)
  if (!selector) return off('no selector (arc.ini selector or selector_env)')

  const pem = this.load_private_key()
  if (!pem) return off('no private key (arc.ini private_key or private_key_env)')
  let key
  try {
    key = crypto.createPrivateKey(pem)
  } catch {
    // Never log the parser's message: it could quote the key.
    return off('the private key is not a PEM private key')
  }
  const type = key.asymmetricKeyType
  if (type !== 'rsa' && type !== 'ed25519') return off(`unsupported key type ${type}`)
  if (type === 'rsa' && key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS) {
    return off(`the RSA key has fewer than ${MIN_RSA_BITS} bits`)
  }

  this.loginfo(`sealing as d=${domain} s=${selector} (${type}-sha256)`)
  return {
    signingDomain: domain,
    selector,
    privateKey: key.export({ type: 'pkcs8', format: 'pem' }),
  }
}

// The PEM from private_key_env (PEM or base64 of PEM) when that variable is
// set, else from the private_key file (relative to Haraka's config directory).
exports.load_private_key = function () {
  const env = from_env(this.cfg.main.private_key_env)
  if (env) return env.includes('-----BEGIN') ? env : Buffer.from(env.replace(/\s+/g, ''), 'base64')
  const file = setting(this.cfg.main.private_key)
  if (!file) return null
  const pem = this.config.get(file, 'binary')
  return pem?.length ? pem : null
}

// The DNS lookups of SPF, DKIM, DMARC and ARC.
exports.resolve = (name, rrtype) => dns.promises.resolve(name, rrtype)

exports.hook_data_post = function (next, connection) {
  const txn = connection.transaction
  if (!this.seal || !txn || !this.wants_seal(connection, txn)) return next()

  // Never rejects mail: a message that cannot be sealed goes on unsealed.
  this.seal_transaction(connection, txn)
    .catch((err) => {
      connection.logerror(this, `not sealed: ${err.message}`)
      txn.results.add(this, { err: err.message })
    })
    .then(() => next())
}

exports.wants_seal = function (connection, txn) {
  const note = txn.notes.arc_seal
  if (note === true || note === false) return note
  return this.cfg.main.seal_relayed && connection.relaying === true
}

exports.seal_transaction = async function (connection, txn) {
  const result = await this.authenticate(connection, txn)
  const fields = header_fields(result.headers)
  const arc = ARC_HEADERS.map((name) =>
    fields.find((f) => f.name.toLowerCase() === name.toLowerCase()),
  )

  if (arc.includes(undefined)) {
    const status = result.arc?.status ?? {}
    const errors = (result.arc?.sealErrors ?? []).map((e) => e.err ?? e.message ?? String(e))
    const reason = errors.length
      ? errors.join('; ')
      : `ARC chain ${status.result}${status.comment ? ` (${status.comment})` : ''}`
    connection.loginfo(this, `not sealed: ${reason}`)
    txn.results.add(this, { skip: reason })
    return
  }
  // Haraka would MIME-encode a non-ASCII value, which breaks the seal.
  if (arc.some((f) => /[\u0080-\uffff]/.test(f.value))) {
    connection.loginfo(this, 'not sealed: non-ASCII text in the ARC headers')
    txn.results.add(this, { skip: 'non-ASCII ARC headers' })
    return
  }

  // Each header goes on top of the previous one: add them bottom-up.
  if (this.cfg.main.add_authentication_results) {
    const ar = fields.find((f) => f.name.toLowerCase() === 'authentication-results')
    if (ar) txn.add_leading_header(ar.name, ar.value)
  }
  for (const field of [...arc].reverse()) txn.add_leading_header(field.name, field.value)

  const i = tag(arc[0].value, 'i')
  const cv = tag(arc[0].value, 'cv')
  connection.loginfo(
    this,
    `sealed i=${i} cv=${cv} d=${this.seal.signingDomain} (${summary(result)})`,
  )
  txn.results.add(this, { pass: 'sealed', instance: Number(i), cv })
}

// Runs mailauth on the message as it is now, streamed (memory does not grow
// with the message size), with the client's IP and HELO and the envelope
// sender before any rewrite (notes.arc_original_sender, e.g. before SRS).
exports.authenticate = function (connection, txn) {
  const input = new PassThrough()
  txn.message_stream.pipe(input, { line_endings: '\r\n' })

  const sender = txn.notes.arc_original_sender
  const run = mailauth.authenticate(input, {
    ip: connection.remote?.ip,
    helo: connection.hello?.host || undefined,
    sender: typeof sender === 'string' ? sender : envelope_address(txn.mail_from),
    mta: this.authserv_id,
    resolver: (name, rrtype) => this.resolve(name, rrtype),
    seal: this.seal,
    // BIMI fetches logos over HTTPS and is not part of an ARC set.
    disableBimi: true,
  })

  // One second under Haraka's plugin timeout, which would answer DENYSOFT.
  const seconds = this.timeout ? this.timeout - 1 : 29
  let timer
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${seconds}s`)), seconds * 1000)
  })
  return Promise.race([run, deadline]).finally(() => {
    clearTimeout(timer)
    // After an error or a timeout the pipe may still be open, and the queue
    // could not read the message. (A no-op once mailauth has read it all.)
    txn.message_stream.unpipe?.()
    input.destroy()
  })
}

function setting(value) {
  return typeof value === 'string' || typeof value === 'number' ? String(value).trim() : ''
}

function from_env(name) {
  const key = setting(name)
  return key ? (process.env[key] ?? '').trim() : ''
}

// user@host of an envelope address: a getter in @haraka/email-address (Haraka 3.3+),
// a method in address-rfc2821 (older Haraka). '' for the null sender.
function envelope_address(address) {
  if (!address) return ''
  return typeof address.address === 'function' ? address.address() : (address.address ?? '')
}

// "Name: value" fields of a CRLF header block, folding kept in the value.
function header_fields(block) {
  return block
    .split(/\r\n(?![ \t])/)
    .filter((raw) => raw.includes(':'))
    .map((raw) => {
      const colon = raw.indexOf(':')
      return { name: raw.slice(0, colon).trim(), value: raw.slice(colon + 1).trimStart() }
    })
}

function tag(value, name) {
  return new RegExp(`(?:^|;)\\s*${name}=([^;\\s]+)`).exec(value)?.[1] ?? ''
}

function summary(result) {
  const dkim = (result.dkim?.results ?? []).map((r) => r.status?.result).join(',') || 'none'
  return [
    `spf=${result.spf?.status?.result ?? 'none'}`,
    `dkim=${dkim}`,
    `dmarc=${result.dmarc?.status?.result ?? 'none'}`,
    `arc=${result.arc?.status?.result ?? 'none'}`,
  ].join(' ')
}
