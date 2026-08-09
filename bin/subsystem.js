#!/usr/bin/env bare
const fs = require('bare-fs')
const path = require('bare-path')
const b4a = require('b4a')
const { UIHost } = require('../lib/ui-host.js')
const { IPC } = require('../lib/ipc.js')
const { roomKey } = require('../lib/room.js')
const { command, flag, arg, summary, header, footer, bail } = require('paparam')

// What runs on a Pi. One subsystem, one app, one physical element.
//
// The app boots, serves its display and works with no network at all. An MCP is strictly optional
// and strictly additive: it observes state and invokes commands the app declared for itself. It
// cannot deploy code — apps ship on the SD card.

// What is actually on the card, as URLs the app can hand straight to its page. Apps are pure JS
// with no filesystem, so the host has to tell them — that is what makes "drop a new jpg in
// subsystem-media and reboot" work with no code change and no controller.
const MEDIA = /\.(jpe?g|png|webp|gif|svg|mp4|webm|ogv|mp3|woff2)$/i

// Dotfiles are never content. A card edited on a Mac gains AppleDouble sidecars — `._puzzle.jpg`
// beside `puzzle.jpg` — and those match MEDIA, sort first, and match an app's name preference just
// as well, so discovery would hand the app 4KB of resource fork instead of the portrait.
function listMedia(dir) {
  try {
    return fs
      .readdirSync(dir)
      .filter((n) => n[0] !== '.' && MEDIA.test(n))
      .sort()
      .map((n) => '/media/' + n)
  } catch {
    return []
  }
}

// `key = value` lines from <assets>/config.txt, with `#` comments. Lives beside the art on the FAT
// boot partition so credentials and the like are editable on the card without a rebuild. Values
// stay host-side: an app validates against them, so a secret never has to reach the page.
function readConfig(dir) {
  let text
  try {
    text = b4a.toString(fs.readFileSync(path.join(dir, 'config.txt')), 'utf8')
  } catch {
    return {}
  }
  const out = {}
  for (const line of text.split('\n')) {
    const s = line.trim()
    if (!s || s[0] === '#') continue
    const eq = s.indexOf('=')
    if (eq < 0) continue
    out[s.slice(0, eq).trim()] = s.slice(eq + 1).trim()
  }
  return out
}

// Which MCP this subsystem answers to, and optionally which private room. Both come off the card
// via config.txt; flags win, so a dev can point one at a local MCP without editing anything.
//
// The MCP key is PUBLIC — losing a card leaks nothing.
function trimmed(file) {
  return fs.existsSync(file) ? b4a.toString(fs.readFileSync(file), 'utf8').trim() : null
}

// The root identity this prop answers to. PUBLIC — losing a card leaks nothing, and the card can
// verify an attestation but never mint one.
function identityKey(cfg, config) {
  const v = cfg.mcp || config.mcp || trimmed(path.join(cfg.appDir, '.mcp-key'))
  return v && /^[0-9a-f]{64}$/i.test(v.trim()) ? v.trim() : null
}

async function main(cfg) {
  const { appDir, host, port, assets, resetAfter } = cfg
  const ui = new UIHost({ host, port, assets, log: (m) => console.log('[ui]', m) })
  await ui.start()

  const media = listMedia(assets)
  const config = readConfig(assets)
  console.log(
    '[subsystem] media from ' +
      assets +
      ' ' +
      (media.length ? '(' + media.join(', ') + ')' : '(empty)')
  )
  const keys = Object.keys(config)
  if (keys.length) console.log('[subsystem] config: ' + keys.join(', '))

  const ipc = new IPC(ui, { media, config, log: (m) => console.log('[app]', m) })

  let resetTimer = null
  if (resetAfter) {
    ipc.observe({
      onReport: (state) => {
        if (state.phase !== 'complete' || resetTimer) return
        resetTimer = setTimeout(() => {
          resetTimer = null
          ipc.command('reset')
        }, resetAfter * 1000)
      }
    })
  }

  const start = require(path.join(appDir, 'index.js'))
  const stop = await start(ipc, () => console.log('[subsystem] app ready'))

  ipc.setState(1) // arm on boot — a subsystem is useful before anything upstream exists
  console.log('[subsystem] ' + path.basename(appDir) + ' armed at ' + ui.url())

  const identity = identityKey(cfg, config)
  let link = null
  if (!identity) {
    console.log(
      '[subsystem] no `mcp` identity configured — running unwatched, which is a valid mode'
    )
  } else {
    const { Link } = require('../lib/link.js')
    link = new Link(ipc, {
      identityKey: identity,
      roomKey: roomKey(cfg.room || config.room), // optional: privacy, never authority
      storeDir: path.join(appDir, '.identity'),
      receiptFile: path.join(appDir, '.receipt'),
      uiPort: port,
      log: (m) => console.log('[link]', m)
    })
    link.open()
  }

  Bare.on('exit', () => {
    if (stop) stop()
    if (link) link.close()
  })
}

// paparam throws a raw Bail otherwise, which reads like a crash for what is usually a typo.
function onBail(b) {
  if (b.err) console.error('sub: ' + b.err.message)
  else if (b.reason === 'UNKNOWN_FLAG') console.error('sub: unknown flag --' + b.flag.name)
  else if (b.reason === 'UNKNOWN_ARG') console.error('sub: unknown command or argument')
  else if (b.reason === 'MISSING_ARG') console.error('sub: missing argument')
  else console.error('sub: ' + b.reason)
  console.error("try 'sub --help'")
  Bare.exit(1)
}

const cli = command(
  'sub',
  bail(onBail),
  header('Run one subsystem: an app, its display, and an optional link to an MCP.'),
  summary('run a subsystem'),
  arg('[appDir]', 'the app to run; defaults to the current directory'),
  flag('--port [port]', 'HTTP port for the display (default 9080)'),
  flag('--host [host]', 'interface to bind (default 127.0.0.1)'),
  flag('--assets [dir]', 'where media and config.txt live (default <appDir>/media)'),
  flag('--reset-after [seconds]', 'reset this long after the app reports complete; 0 disables'),
  flag('--mcp [64-hex]', 'public key of the MCP to answer to; overrides config.txt'),
  flag('--room [secret]', 'room secret, if the fleet is private'),
  footer('a subsystem runs whether or not anyone is watching — that is the point'),
  async (cmd) => {
    const appDir = path.resolve(cmd.args.appDir || '.')
    // Checked before anything binds a port: starting the UI host and *then* failing to find the app
    // leaves a listener up and buries the real cause under a module error.
    if (!fs.existsSync(path.join(appDir, 'index.js'))) {
      console.error('[subsystem] no index.js in ' + appDir)
      console.error('[subsystem] usage: sub <appDir>')
      return Bare.exit(1)
    }
    await main({
      appDir,
      port: Number(cmd.flags.port || 9080),
      host: cmd.flags.host || '127.0.0.1',
      // On a Pi this points at the FAT boot partition, so the art is editable by plugging the card
      // into a laptop. Locally it is just the app's own media dir.
      assets: cmd.flags.assets || path.join(appDir, 'media'),
      resetAfter: Number(cmd.flags.resetAfter || 0),
      mcp: cmd.flags.mcp,
      room: cmd.flags.room
    })
  }
)

const parsed = cli.parse(Bare.argv.slice(2))
if (parsed && parsed.running) {
  parsed.running.catch((e) => {
    console.error('[subsystem] fatal', e)
    Bare.exit(1)
  })
}
