'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { PassThrough } = require('node:stream')
const { afterEach, describe, it, mock } = require('node:test')

const mailauth = require('mailauth')

const arcPlugin = require('../index.js')

// No network: every DNS answer comes from this table.
const keys = {
  sender: rsaKey(), // example.com, the author's DKIM key
  hop1: rsaKey(), // forwarder.test
  hop2: rsaKey(), // second.test
}
const TXT = {
  'sel._domainkey.example.com': dkimRecord(keys.sender),
  'arc._domainkey.forwarder.test': dkimRecord(keys.hop1),
  'arc2._domainkey.second.test': dkimRecord(keys.hop2),
  'example.com': 'v=spf1 ip4:203.0.113.9 -all',
  'forwarder.test': 'v=spf1 ip4:198.51.100.7 -all',
  '_dmarc.example.com': 'v=DMARC1; p=reject',
}

async function resolver(name, rrtype) {
  const record = TXT[name.toLowerCase()]
  if (rrtype === 'TXT' && record) return [[record]]
  const err = new Error(`query${rrtype} ENOTFOUND ${name}`)
  err.code = 'ENOTFOUND'
  throw err
}

function rsaKey(bits = 2048) {
  return crypto.generateKeyPairSync('rsa', { modulusLength: bits })
}

function dkimRecord(pair) {
  return `v=DKIM1; k=rsa; p=${pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`
}

function pem(pair, type = 'pkcs8') {
  return pair.privateKey.export({ type, format: 'pem' })
}

// A message as the author's server sent it: DKIM-signed by example.com.
async function authorMessage() {
  const message = [
    'From: Boss <boss@example.com>',
    'To: support@forwarder.test',
    'Subject: Invoice',
    'Date: Tue, 10 Nov 2026 10:00:00 +0000',
    'Message-ID: <invoice-1@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Please find the invoice attached.',
    '',
  ].join('\r\n')
  const { signatures } = await mailauth.dkimSign(message, {
    signatureData: [
      { signingDomain: 'example.com', selector: 'sel', privateKey: pem(keys.sender) },
    ],
  })
  return signatures + message
}

const HOP1 = { domain: 'forwarder.test', selector: 'arc', me: 'mx.forwarder.test', key: keys.hop1 }
const HOP2 = { domain: 'second.test', selector: 'arc2', me: 'mx.second.test', key: keys.hop2 }

// A plugin object as Haraka builds it: the exports, config, log methods.
function makePlugin({ hop = HOP1, main = {}, files = { 'arc/private.pem': pem(hop.key) } } = {}) {
  const logs = []
  const ini = {
    main: {
      enabled: true,
      seal_relayed: true,
      add_authentication_results: false,
      domain: hop.domain,
      selector: hop.selector,
      private_key: 'arc/private.pem',
      ...main,
    },
  }
  const plugin = Object.assign(Object.create(arcPlugin), {
    name: 'arc',
    timeout: 30,
    logs,
    config: {
      get(name) {
        if (name === 'arc.ini') return structuredClone(ini)
        if (name === 'me') return hop.me
        return name in files ? Buffer.from(files[name]) : null
      },
    },
    resolve: resolver,
  })
  for (const level of ['debug', 'info', 'warn', 'error']) {
    plugin[`log${level}`] = (msg) => logs.push(`${level}: ${msg}`)
  }
  plugin.register()
  return plugin
}

// The few members of a Haraka connection and transaction the plugin uses.
function makeConnection(
  raw,
  { ip = '203.0.113.9', helo = 'mx.example.com', relaying = true } = {},
) {
  const leading = []
  const results = []
  const logs = []
  const transaction = {
    mail_from: { address: 'boss@example.com' },
    notes: {},
    results: { add: (_plugin, result) => results.push(result) },
    message_stream: {
      unpiped: 0,
      pipe(destination) {
        const source = new PassThrough()
        source.pipe(destination)
        source.end([...leading, ''].join('\r\n') + raw)
      },
      unpipe() {
        this.unpiped++
      },
    },
    add_leading_header(name, value) {
      leading.unshift(`${name}: ${value}`)
    },
  }
  const connection = {
    remote: { ip },
    hello: { host: helo },
    relaying,
    transaction,
    loginfo: (_plugin, msg) => logs.push(`info: ${msg}`),
    logerror: (_plugin, msg) => logs.push(`error: ${msg}`),
  }
  return {
    connection,
    transaction,
    results,
    logs,
    leadingNames: () => leading.map((h) => h.slice(0, h.indexOf(':'))),
    message: () => [...leading, ''].join('\r\n') + raw,
  }
}

function runHook(plugin, connection) {
  return new Promise((resolve) => {
    plugin.hook_data_post((...args) => resolve(args), connection)
  })
}

// How the next receiver sees the message (here: another hop, with its own IP).
function verifyArc(message) {
  return mailauth.authenticate(message, {
    ip: '192.0.2.25',
    helo: 'mx.receiver.test',
    sender: 'bounces@forwarder.test',
    mta: 'mx.receiver.test',
    resolver,
    disableBimi: true,
  })
}

const ARC_SET = ['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results']

describe('sealing', () => {
  it('seals relayed mail: the ARC set on top, i=1 cv=none, valid for mailauth', async () => {
    const raw = await authorMessage()
    const plugin = makePlugin()
    const hop = makeConnection(raw)

    assert.deepEqual(await runHook(plugin, hop.connection), [])
    assert.deepEqual(hop.leadingNames(), ARC_SET)
    const sealed = hop.message()
    assert.match(
      sealed,
      /^ARC-Seal: i=1; a=rsa-sha256; t=\d+; cv=none; d=forwarder\.test;\r\n s=arc;/,
    )
    assert.ok(sealed.endsWith(raw), 'the message itself is not changed')
    assert.deepEqual(hop.results, [{ pass: 'sealed', instance: 1, cv: 'none' }])

    const { arc } = await verifyArc(sealed)
    assert.equal(arc.status.result, 'pass')
    assert.equal(arc.i, 1)
    assert.equal(arc.signature.signingDomain, 'forwarder.test')
    // What the forwarder saw, recorded in the ARC-Authentication-Results.
    const seen = arc.authenticationResults
    assert.equal(seen.mta, 'mx.forwarder.test')
    assert.equal(seen.spf.result, 'pass')
    assert.equal(seen.spf.smtp.mailfrom, 'boss@example.com')
    assert.equal(seen.dkim[0].result, 'pass')
    assert.equal(seen.dmarc.result, 'pass')

    // The check is real: a changed body breaks the chain.
    const tampered = sealed.replace('the invoice', 'the new invoice')
    assert.equal((await verifyArc(tampered)).arc.status.result, 'fail')
  })

  it('a second hop seals on top of an existing set: i=2 cv=pass', async () => {
    const first = makeConnection(await authorMessage())
    await runHook(makePlugin(), first.connection)

    // forwarder.test relays the sealed message to second.test, which forwards it again.
    const second = makeConnection(first.message(), {
      ip: '198.51.100.7',
      helo: 'mx.forwarder.test',
    })
    second.transaction.mail_from = { address: 'bounces@forwarder.test' }
    assert.deepEqual(await runHook(makePlugin({ hop: HOP2 }), second.connection), [])

    const sealed = second.message()
    assert.match(sealed, /^ARC-Seal: i=2; a=rsa-sha256; t=\d+; cv=pass; d=second\.test;/)
    assert.deepEqual(second.results, [{ pass: 'sealed', instance: 2, cv: 'pass' }])
    const { arc } = await verifyArc(sealed)
    assert.equal(arc.status.result, 'pass')
    assert.equal(arc.i, 2)
    assert.equal(arc.signature.signingDomain, 'second.test')
  })

  it('notes.arc_seal seals mail that is not relayed, with SPF for notes.arc_original_sender', async () => {
    const hop = makeConnection(await authorMessage(), { relaying: false })
    // An SRS rewrite already happened: SPF must be checked for the sender before it.
    hop.transaction.mail_from = { address: 'SRS0=abcd=TT=example.com=boss@forwarder.test' }
    hop.transaction.notes.arc_seal = true
    hop.transaction.notes.arc_original_sender = 'boss@example.com'

    await runHook(makePlugin(), hop.connection)
    const { arc } = await verifyArc(hop.message())
    assert.equal(arc.status.result, 'pass')
    assert.equal(arc.authenticationResults.spf.result, 'pass')
    assert.equal(arc.authenticationResults.spf.smtp.mailfrom, 'boss@example.com')
  })

  it('reads the envelope sender of older Haraka, where address is a method', async () => {
    const hop = makeConnection(await authorMessage())
    hop.transaction.mail_from = { address: () => 'boss@example.com' }
    await runHook(makePlugin(), hop.connection)
    const { arc } = await verifyArc(hop.message())
    assert.equal(arc.authenticationResults.spf.smtp.mailfrom, 'boss@example.com')
  })

  it('add_authentication_results puts the Authentication-Results under the ARC set', async () => {
    const hop = makeConnection(await authorMessage())
    await runHook(makePlugin({ main: { add_authentication_results: true } }), hop.connection)
    assert.deepEqual(hop.leadingNames(), [...ARC_SET, 'Authentication-Results'])
    assert.match(hop.message(), /^Authentication-Results: mx\.forwarder\.test;\r\n dkim=pass /m)
    assert.equal((await verifyArc(hop.message())).arc.status.result, 'pass')
  })
})

describe('when it does not seal', () => {
  it('never seals ordinary inbound mail, or a message with notes.arc_seal = false', async () => {
    const plugin = makePlugin()
    const inbound = makeConnection(await authorMessage(), { relaying: false })
    const optedOut = makeConnection(await authorMessage())
    optedOut.transaction.notes.arc_seal = false
    for (const hop of [inbound, optedOut]) {
      assert.deepEqual(await runHook(plugin, hop.connection), [])
      assert.deepEqual(hop.leadingNames(), [])
    }
  })

  it('seal_relayed=false: relayed mail only with notes.arc_seal', async () => {
    const plugin = makePlugin({ main: { seal_relayed: false } })
    const relayed = makeConnection(await authorMessage())
    await runHook(plugin, relayed.connection)
    assert.deepEqual(relayed.leadingNames(), [])

    relayed.transaction.notes.arc_seal = true
    await runHook(plugin, relayed.connection)
    assert.deepEqual(relayed.leadingNames(), ARC_SET)
  })

  it('enabled=false: never seals', async () => {
    const plugin = makePlugin({ main: { enabled: false } })
    assert.equal(plugin.seal, null)
    const hop = makeConnection(await authorMessage())
    hop.transaction.notes.arc_seal = true
    await runHook(plugin, hop.connection)
    assert.deepEqual(hop.leadingNames(), [])
  })

  it('a broken chain is sealed once with cv=fail, then never again', async () => {
    const first = makeConnection(await authorMessage())
    await runHook(makePlugin(), first.connection)
    // Changed after the first seal (a mailing list footer, say).
    const changed = first.message().replace('the invoice', 'the new invoice')
    const second = makeConnection(changed, { ip: '198.51.100.7', helo: 'mx.forwarder.test' })
    await runHook(makePlugin({ hop: HOP2 }), second.connection)
    assert.deepEqual(second.results, [{ pass: 'sealed', instance: 2, cv: 'fail' }])

    const third = makeConnection(second.message(), { ip: '198.51.100.7', helo: 'mx.second.test' })
    assert.deepEqual(await runHook(makePlugin(), third.connection), [])
    assert.deepEqual(third.leadingNames(), [])
    assert.equal(third.results.length, 1)
    assert.match(third.results[0].skip, /^ARC chain fail/)
    assert.match(third.logs[0], /^info: not sealed: ARC chain fail/)
  })

  it('a non-ASCII ARC header (an SMTPUTF8 sender) is not sealed: Haraka would encode it', async () => {
    const hop = makeConnection(await authorMessage())
    hop.transaction.mail_from = { address: 'bøss@example.com' }
    assert.deepEqual(await runHook(makePlugin(), hop.connection), [])
    assert.deepEqual(hop.leadingNames(), [])
    assert.deepEqual(hop.results, [{ skip: 'non-ASCII ARC headers' }])
  })
})

describe('errors never reject mail', () => {
  afterEach(() => mock.restoreAll())

  it('mailauth throwing: next() without a code, the message unchanged', async () => {
    mock.method(mailauth, 'authenticate', async () => {
      throw new Error('parser exploded')
    })
    const raw = await authorMessage()
    const hop = makeConnection(raw)
    assert.deepEqual(await runHook(makePlugin(), hop.connection), [])
    assert.equal(hop.message(), raw)
    assert.deepEqual(hop.results, [{ err: 'parser exploded' }])
    assert.deepEqual(hop.logs, ['error: not sealed: parser exploded'])
    // The queue must be able to read the message next.
    assert.equal(hop.transaction.message_stream.unpiped, 1)
  })

  it('DNS that never answers: unsealed one second before the Haraka plugin timeout', async () => {
    const plugin = makePlugin()
    plugin.timeout = 1.2 // seconds; the plugin gives up after 0.2
    plugin.resolve = () => new Promise(() => {})
    const hop = makeConnection(await authorMessage())
    const started = Date.now()
    assert.deepEqual(await runHook(plugin, hop.connection), [])
    assert.ok(Date.now() - started < 1000)
    assert.deepEqual(hop.leadingNames(), [])
    assert.match(hop.results[0].err, /timed out/)
    assert.equal(hop.transaction.message_stream.unpiped, 1)
  })
})

describe('the key', () => {
  const saved = { ...process.env }
  afterEach(() => {
    process.env = { ...saved }
  })

  it('from private_key_env (PEM or base64 of PEM) and selector_env', async () => {
    for (const value of [pem(keys.hop1, 'pkcs1'), Buffer.from(pem(keys.hop1)).toString('base64')]) {
      process.env.TEST_ARC_KEY = value
      process.env.TEST_ARC_SELECTOR = 'arc'
      const plugin = makePlugin({
        main: {
          selector: 'ignored',
          selector_env: 'TEST_ARC_SELECTOR',
          private_key: '',
          private_key_env: 'TEST_ARC_KEY',
        },
        files: {},
      })
      assert.equal(plugin.seal.selector, 'arc')
      const hop = makeConnection(await authorMessage())
      await runHook(plugin, hop.connection)
      assert.equal((await verifyArc(hop.message())).arc.status.result, 'pass')
    }
  })

  it('without a usable key or domain: sealing off, logged once at register', () => {
    const cases = [
      [{ private_key: '' }, {}, /no private key/],
      [{ private_key_env: 'TEST_ARC_UNSET', private_key: '' }, {}, /no private key/],
      [{}, { 'arc/private.pem': 'not a key' }, /not a PEM private key/],
      [{}, { 'arc/private.pem': pem(rsaKey(512)) }, /fewer than 1024 bits/],
      [{ domain: '' }, undefined, /no domain/],
      [{ selector: '' }, undefined, /no selector/],
    ]
    for (const [main, files, reason] of cases) {
      const plugin = makePlugin({ main, files })
      assert.equal(plugin.seal, null)
      assert.equal(plugin.logs.length, 1)
      assert.match(plugin.logs[0], /^error: sealing disabled: /)
      assert.match(plugin.logs[0], reason)
      // The key never reaches the log.
      assert.doesNotMatch(plugin.logs[0], /BEGIN|not a key/)
    }
  })

  it('logs the identity it seals as', () => {
    assert.deepEqual(makePlugin().logs, ['info: sealing as d=forwarder.test s=arc (rsa-sha256)'])
  })
})
