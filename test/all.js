const test = require('brittle')
const b4a = require('b4a')
const cenc = require('compact-encoding')
const protocol = require('../lib/protocol.js')
const { roomKey, topic } = require('../lib/room.js')
const attest = require('../lib/attest.js')
const crypto = require('hypercore-crypto')

test('every protocol message round-trips', function (t) {
  const messages = {
    describe: { appId: 'counter', appVersion: '1.0.0', caps: '{"id":"counter"}' },
    event: { name: 'bumped', payload: '{"count":3}', ts: 1770000000 },
    stateReport: { state: '{"count":3}', ts: 1770000000 },
    commandResult: { id: 7, ok: false, result: '"nope"' },
    command: { id: 7, name: 'bump', args: '{}' },
    capability: { proof: b4a.alloc(32, 9) },
    fleetOperator: { key: b4a.alloc(32, 3), role: 'pending', online: true }
  }

  for (const [name, value] of Object.entries(messages)) {
    t.alike(cenc.decode(protocol[name], cenc.encode(protocol[name], value)), value, name)
  }
})

test('a room secret is any string, hashed to 32 bytes', function (t) {
  const key = roomKey('a shared phrase')

  t.is(key.length, 32)
  t.alike(roomKey('a shared phrase'), key, 'stable across calls')
  t.unlike(roomKey('a different phrase'), key, 'different secrets differ')
  t.is(roomKey(''), null, 'a blank secret is no secret')
  t.is(roomKey(null), null)
})

test('a 64-char hex secret is taken verbatim, not rehashed', function (t) {
  const raw = b4a.alloc(32, 3)

  t.alike(roomKey(b4a.toString(raw, 'hex')), raw)
})

test('the topic is derived from the secret and is not the secret', function (t) {
  const key = roomKey('a shared phrase')
  const t1 = topic(key)

  t.is(t1.length, 32)
  t.unlike(t1, key, 'publishing the topic must not publish the secret')
  t.alike(topic(roomKey('a shared phrase')), t1, 'stable, so peers agree')
  t.unlike(topic(roomKey('another room')), t1, 'rooms do not collide')
})

// The trust boundary. A card holds a PUBLIC identity key; everything below is what stops that from
// being enough for someone else to command a prop.
test('an attestation must chain to our identity AND name this peer', async function (t) {
  const words = attest.generateMnemonic()
  const ours = await attest.identityKeyOf(words)
  const mcpBox = crypto.keyPair()
  const proof = await attest.attest(words, mcpBox.publicKey)

  t.ok(attest.verify(proof, ours, mcpBox.publicKey), 'the real MCP is accepted')

  // Replay: a genuine proof, presented by a peer it was not minted for.
  const attacker = crypto.keyPair()
  t.absent(attest.verify(proof, ours, attacker.publicKey), 'not replayable onto another peer')

  // A different root entirely — someone who ran `mcp identity` themselves.
  const theirWords = attest.generateMnemonic()
  const theirs = await attest.identityKeyOf(theirWords)
  const theirProof = await attest.attest(theirWords, attacker.publicKey)
  t.absent(attest.verify(theirProof, ours, attacker.publicKey), 'a foreign identity is refused')
  t.absent(
    attest.verify(proof, theirs, mcpBox.publicKey),
    'our proof does not satisfy their identity'
  )

  // Nothing, and rubbish.
  t.absent(attest.verify(null, ours, mcpBox.publicKey), 'no proof is refused')
  t.absent(attest.verify(b4a.alloc(0), ours, mcpBox.publicKey), 'an empty proof is refused')
  // Malformed bytes must return null, never throw: an uncaught throw on a supervised prop is a
  // restart, and a remote restart loop is a denial of service against a device in a venue.
  for (const junk of [b4a.alloc(139, 7), b4a.alloc(1, 255), b4a.alloc(300, 0xab), b4a.from([1])]) {
    t.absent(attest.verify(junk, ours, mcpBox.publicKey), 'garbage is refused, not thrown')
  }

  // Tampered: flip a byte of a valid proof.
  const bent = b4a.from(proof)
  bent[bent.byteLength - 1] ^= 0xff
  t.absent(attest.verify(bent, ours, mcpBox.publicKey), 'a tampered proof is refused')
})

test('a card can verify an attestation but never mint one', async function (t) {
  const words = attest.generateMnemonic()
  const ours = await attest.identityKeyOf(words)
  const attacker = crypto.keyPair()

  // `ours` is the whole of what a card carries. Attesting with it must be impossible, not merely
  // produce something that fails later.
  let minted = null
  try {
    minted = await attest.attest(ours, attacker.publicKey)
  } catch {
    minted = null
  }
  t.absent(minted, 'the public identity key cannot stand in for the mnemonic')

  // Nor does a guessed mnemonic produce anything our identity accepts.
  const wrong = attest.generateMnemonic()
  const forged = await attest.attest(wrong, attacker.publicKey)
  t.absent(attest.verify(forged, ours, attacker.publicKey), 'a proof from other words is refused')
})

test('an older attestation is refused once a newer one has been seen', async function (t) {
  const words = attest.generateMnemonic()
  const ours = await attest.identityKeyOf(words)
  const leaked = crypto.keyPair()
  const replacement = crypto.keyPair()

  const oldProof = await attest.attest(words, leaked.publicKey)
  const first = attest.verify(oldProof, ours, leaked.publicKey)
  t.ok(first, 'accepted before rotation')

  // Epochs are second-granular, so a rotation has to be a second apart to be distinguishable.
  await new Promise((resolve) => setTimeout(resolve, 1100))
  const newProof = await attest.attest(words, replacement.publicKey)
  const second = attest.verify(newProof, ours, replacement.publicKey)
  t.ok(second, 'the replacement box is accepted')

  t.absent(
    attest.verify(oldProof, ours, leaked.publicKey, second.receipt),
    'the leaked key is dead once the prop has seen the newer epoch'
  )
  t.ok(
    attest.verify(newProof, ours, replacement.publicKey, first.receipt),
    'a newer proof still passes an older receipt'
  )
})

// ── downloads ───────────────────────────────────────────────────────────────

const http = require('bare-http1')
const fs = require('bare-fs')
const os = require('bare-os')
const path = require('bare-path')
const { download } = require('../lib/download.js')
const { UIHost } = require('../lib/ui-host.js')

// A real server, so redirects, headers and streaming are the real thing rather than a mock's idea
// of them.
async function serve(t, routes) {
  const hits = {}
  const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0]
    hits[url] = (hits[url] || 0) + 1
    const r = routes[url]
    if (!r) {
      res.writeHead(404)
      return res.end()
    }
    if (r.redirect) {
      res.writeHead(302, { Location: r.redirect })
      return res.end()
    }
    res.writeHead(200, { 'Content-Type': r.type }) // bare-http1 sets Content-Length from end()
    res.end(r.body)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.teardown(() => new Promise((resolve) => server.close(resolve)))
  return { base: 'http://127.0.0.1:' + server.address().port, hits }
}

function tmp() {
  const dir = path.join(
    os.tmpdir(),
    'dl-test-' + Date.now() + '-' + Math.floor(Math.random() * 1e6)
  )
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

test('a download lands whole, reports progress, and is never fetched twice', async function (t) {
  const body = b4a.alloc(300 * 1024, 7)
  const { base, hits } = await serve(t, { '/reel.mp4': { type: 'video/mp4', body } })
  const dir = tmp()
  const seen = []

  const name = await download(base + '/reel.mp4', dir, { onProgress: (p) => seen.push(p) })
  t.ok(/^dl-[0-9a-f]{16}\.mp4$/.test(name), 'named by the URL, keeping the extension')
  t.alike(fs.readFileSync(path.join(dir, name)), body, 'every byte arrived')
  t.alike(
    seen[seen.length - 1],
    { received: body.byteLength, total: body.byteLength },
    'ends at 100%'
  )
  t.absent(
    fs.readdirSync(dir).some((n) => n.endsWith('.part')),
    'no .part left behind'
  )

  t.is(await download(base + '/reel.mp4', dir), name, 'same URL, same file')
  t.is(hits['/reel.mp4'], 2, 'the second call only asked; it did not save again')
  t.is(fs.readdirSync(dir).length, 1)
})

test('a link with no extension takes one from its content type, through a redirect', async function (t) {
  const body = b4a.from('fake jpeg')
  const { base } = await serve(t, {
    '/share': { redirect: '/file' },
    '/file': { type: 'image/jpeg; charset=binary', body }
  })
  const name = await download(base + '/share', tmp())
  t.ok(name.endsWith('.jpg'), name)
})

test('a failed or unservable download leaves nothing behind', async function (t) {
  const { base } = await serve(t, { '/notes.txt': { type: 'text/plain', body: b4a.from('hi') } })
  const dir = tmp()
  await t.exception(download(base + '/missing.mp4', dir), /HTTP 404/)
  await t.exception(download(base + '/notes.txt', dir), /not a media file/)
  await t.exception(download('file:///etc/passwd', dir), /not an http/)
  t.is(fs.readdirSync(dir).length, 0)
})

test('the UI host serves downloads under /media/, but the card wins a name', async function (t) {
  const assets = tmp()
  const downloads = tmp()
  fs.writeFileSync(path.join(downloads, 'dl-abc.jpg'), 'downloaded')
  fs.writeFileSync(path.join(downloads, 'same.jpg'), 'downloaded')
  fs.writeFileSync(path.join(assets, 'same.jpg'), 'from the card')
  fs.writeFileSync(path.join(downloads, 'dl-abc.jpg.part'), 'half')

  const ui = new UIHost({ port: 0, assets, downloads })
  await ui.start()
  t.teardown(() => ui.stop())
  const base = 'http://127.0.0.1:' + ui.server.address().port
  const get = (p) =>
    new Promise((resolve) => {
      http.get(base + p, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () =>
          resolve({ status: res.statusCode, body: b4a.toString(b4a.concat(chunks)) })
        )
      })
    })

  t.alike(await get('/media/dl-abc.jpg'), { status: 200, body: 'downloaded' })
  t.alike(await get('/media/same.jpg'), { status: 200, body: 'from the card' })
  t.is((await get('/media/dl-abc.jpg.part')).status, 404, 'a half-written file is never served')
})
