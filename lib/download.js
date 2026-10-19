const fs = require('bare-fs')
const path = require('bare-path')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const fetch = require('bare-fetch')
const { MIME } = require('./ui-host.js')

const STALL_MS = 30000 // no bytes for this long and the download is dead, not slow
const PROGRESS_MS = 500

// Fetch a URL onto the device once, so a controller can point a prop at new art and have it
// survive a reboot, play with the venue offline, and load past a kiosk that refuses the internet.
//
// Named by the URL's hash: the same URL is never fetched twice, and two URLs never collide. Bytes
// land in a .part file renamed into place only once complete, so a half-written file is never what
// the page loads — a failed download leaves nothing behind and the prop keeps its current art.
//
// Resolves to the file's name in `dir`. Only what the UI host will serve is accepted.
async function download(url, dir, { onProgress = () => {} } = {}) {
  const u = new URL(url)
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('not an http(s) URL')

  const res = await fetch(url)
  if (!res.ok) throw new Error('HTTP ' + res.status)

  // The URL's own extension if it has a servable one, else the server's content type — hosting
  // services hand out links like /file?id=… that say nothing about what they point at.
  const type = String(res.headers.get('content-type') || '')
    .split(';')[0]
    .trim()
  let ext = path.extname(u.pathname).toLowerCase()
  if (!MIME[ext]) ext = Object.keys(MIME).find((e) => MIME[e] === type) || ''
  if (!ext) throw new Error('not a media file (' + (type || 'no content type') + ')')

  const name = 'dl-' + b4a.toString(crypto.hash(b4a.from(url)), 'hex').slice(0, 16) + ext
  const file = path.join(dir, name)
  // An explicit reader, because only the reader may cancel a stream it holds locked.
  const reader = res.body.getReader()
  if (fs.existsSync(file)) {
    await reader.cancel()
    return name
  }

  fs.mkdirSync(dir, { recursive: true })
  const part = file + '.part'
  const total = Number(res.headers.get('content-length')) || 0
  const out = fs.createWriteStream(part)
  let received = 0
  let said = 0
  let stall = null
  let stalled = false
  const alive = () => {
    clearTimeout(stall)
    stall = setTimeout(() => {
      stalled = true // a cancelled stream may just end, which must not read as complete
      reader.cancel(new Error('stalled'))
    }, STALL_MS)
  }

  try {
    alive()
    while (true) {
      const { done, value: chunk } = await reader.read()
      if (done) break
      alive()
      received += chunk.byteLength
      if (!out.write(chunk)) await new Promise((resolve) => out.once('drain', resolve))
      if (Date.now() - said >= PROGRESS_MS) {
        said = Date.now()
        onProgress({ received, total })
      }
    }
    if (stalled) throw new Error('stalled — no data for ' + STALL_MS / 1000 + 's')
    await new Promise((resolve, reject) => {
      out.once('error', reject)
      out.once('close', resolve)
      out.end()
    })
  } catch (err) {
    out.destroy()
    fs.rmSync(part, { force: true })
    throw err
  } finally {
    clearTimeout(stall)
  }

  if (total && received !== total) {
    fs.rmSync(part, { force: true })
    throw new Error('cut short at ' + received + ' of ' + total + ' bytes')
  }
  fs.renameSync(part, file)
  onProgress({ received, total: total || received })
  return name
}

module.exports = { download }
