const b4a = require('b4a')
const fs = require('bare-fs')
const Hyperswarm = require('hyperswarm')
const { loadOrCreateKeyPair } = require('./identity.js')
const { createChannels } = require('./channels.js')
const { topic, guard } = require('./room.js')
const attest = require('./attest.js')

// Optional presence in a fleet. Strictly additive: the app is already running and serving its
// display before this announces, and it keeps running whether or not anyone ever connects. A dead
// venue network must never blank a subsystem, so nothing here is on the boot path.
//
// A subsystem trusts exactly ONE identity: the root identity whose PUBLIC key is on its card. That
// key is worth nothing to whoever steals the card — it can verify an attestation but never mint one,
// because minting needs the identity's secret, which lives offline with the mnemonic.
//
// The MCP presents a proof that its device key was attested by that identity. So the MCP machine can
// be swapped or replaced and every prop still accepts it, with no reflashing — which is the whole
// reason the anchor is an identity rather than one box's key.
//
// Operators are never a concept here: they talk to the MCP, never to us.
//
// An optional room secret mixes into the topic. It hides the fleet from someone who has learned the
// MCP key; it never decides authority.
//
// Nothing here can deploy code — apps are updated by flashing an SD card.
const ATTEST_MS = 10000

function readReceipt(file) {
  if (!file) return undefined
  try {
    return fs.readFileSync(file)
  } catch {
    return undefined
  }
}

class Link {
  constructor(ipc, opts = {}) {
    this.ipc = ipc
    this.identityKey = asKey(opts.identityKey)
    this.roomKey = opts.roomKey || null
    this.storeDir = opts.storeDir
    // The newest attestation epoch we have accepted, as an opaque marker. See _acceptReceipt.
    this.receiptFile = opts.receiptFile || null
    this.receipt = readReceipt(this.receiptFile)
    this.log = opts.log || (() => {})
    this.bootstrap = opts.bootstrap || undefined
    this.uiPort = opts.uiPort || 0

    this.swarm = null
    this.keyPair = null
    this.mcp = null // the one connected peer, or null

    ipc.observe({
      onReport: (state) =>
        this._send('sendStateReport', { state: JSON.stringify(state ?? null), ts: now() }),
      onEvent: (name, payload) =>
        this._send('sendEvent', { name, payload: JSON.stringify(payload ?? null), ts: now() }),
      onDescribe: (caps) => this._send('sendDescribe', describeOf(caps, this.uiPort))
    })
  }

  identity() {
    return b4a.toString(this.keyPair.publicKey, 'hex')
  }

  open() {
    this.keyPair = loadOrCreateKeyPair(this.storeDir)
    this.swarm = new Hyperswarm({ keyPair: this.keyPair, bootstrap: this.bootstrap })
    this.swarm.on('connection', (socket) => this._onConnection(socket))

    const t = topic(this.identityKey, this.roomKey)
    this.log('identity ' + this.identity())
    this.log(
      'identity ' +
        hex(this.identityKey) +
        (this.roomKey ? ' · private room' : '') +
        ' — announcing on ' +
        hex(t)
    )
    // We look for the MCP; we never announce. Two subsystems therefore never discover each other,
    // and nothing can enumerate a fleet by listening on the topic.
    this.swarm.join(t, { server: false, client: true })
  }

  // Anyone can find the topic; only the MCP gets a conversation. Everyone else is dropped before we
  // disclose that an app even exists here.
  _onConnection(socket) {
    socket.on('error', () => {})

    const tag = hex(socket.remotePublicKey)

    // We can no longer judge a peer by its key alone, so the connection is allowed to open and then
    // told nothing until it proves itself. Two independent gates, and BOTH must pass: the optional
    // room secret, and an attestation from our identity naming this exact peer. Until then we send
    // no state, disclose no manifest, and run no command — a peer that fails learns only that
    // something answered.
    let gate = null
    let earlyCapability = null
    let attested = false
    let attached = false

    const attach = () => {
      if (attached || !attested || !gate.verified) return
      attached = true
      this.mcp = channels
      this.log('mcp attached')
      // Catch it up: the app booted long before this connection existed.
      if (this.ipc.caps) channels.sendDescribe(describeOf(this.ipc.caps, this.uiPort))
      if (this.ipc.state)
        channels.sendStateReport({ state: JSON.stringify(this.ipc.state), ts: now() })
    }

    const onAttestation = (m) => {
      if (attested) return
      const info = attest.verify(m.proof, this.identityKey, socket.remotePublicKey, this.receipt)
      if (!info) {
        this.log('refused ' + tag + ' — not attested by our identity')
        socket.destroy()
        return
      }
      attested = true
      this._acceptReceipt(info.receipt)
      attach()
    }

    // Same ordering trap as the MCP side: either message can land while createChannels is still
    // running, before `gate` exists. Buffer instead of throwing into protomux's dispatch — that
    // destroys the stream and the peer reconnects into the same trap forever.
    let earlyAttestation = null
    const channels = createChannels(socket, {
      onCapability: (m) => (gate ? gate.onCapability(m) : (earlyCapability = m)),
      onAttestation: (m) => (gate ? onAttestation(m) : (earlyAttestation = m)),
      onCommand: (m) => {
        if (attached) this._onCommand(m, channels)
      }
    })

    gate = guard(socket, channels, this.roomKey, {
      log: (m) => this.log(tag + ': ' + m),
      onVerified: attach
    })

    // An unattested peer must not sit on the connection forever holding it open.
    const timer = setTimeout(() => {
      if (attested) return
      this.log('refused ' + tag + ' — never sent an attestation')
      socket.destroy()
    }, ATTEST_MS)

    if (earlyCapability) gate.onCapability(earlyCapability)
    if (earlyAttestation) onAttestation(earlyAttestation)

    socket.on('close', () => {
      clearTimeout(timer)
      gate.destroy()
      if (this.mcp !== channels) return
      this.mcp = null
      this.log('mcp detached — the app keeps running')
    })
  }

  // Epochs only move forward: once we have seen a proof minted at some point, older ones are dead.
  // Persisted, so a power cycle cannot walk a revoked MCP key back in.
  _acceptReceipt(receipt) {
    if (!this.receiptFile || !receipt) return
    this.receipt = receipt
    try {
      fs.writeFileSync(this.receiptFile, receipt)
    } catch {
      // A read-only or full filesystem must not stop the prop running. We keep the receipt in
      // memory for this boot, which still blocks a downgrade until the next restart.
    }
  }

  async _onCommand(m, channels) {
    let ok = true
    let result = null
    try {
      result = await this.ipc.command(m.name, parse(m.args))
    } catch (e) {
      ok = false
      result = String((e && e.message) || e)
    }
    channels.sendCommandResult({ id: m.id, ok, result: JSON.stringify(result ?? null) })
  }

  _send(method, msg) {
    if (!this.mcp) return
    try {
      this.mcp[method](msg)
    } catch {
      /* dropped; close will clean it up */
    }
  }

  async close() {
    if (this.swarm) await this.swarm.destroy()
  }
}

// `uiPort` is the platform's to add, not the app's: it comes from --port, not from anything the app
// declared. Loopback-bound, so it is not an address anyone can reach — it is what a console needs to
// tell an operator how to tunnel in and look at the screen.
function describeOf(caps, uiPort) {
  return {
    appId: (caps && caps.id) || 'unknown',
    appVersion: (caps && caps.version) || '0.0.0',
    caps: JSON.stringify({ ...caps, uiPort })
  }
}

function asKey(k) {
  return typeof k === 'string' ? b4a.from(k.trim(), 'hex') : k
}
function hex(k) {
  return b4a.toString(k, 'hex').slice(0, 12) + '…'
}
function now() {
  return Math.floor(Date.now() / 1000)
}
function parse(json) {
  try {
    return JSON.parse(json)
  } catch {
    return null
  }
}

module.exports = { Link }
