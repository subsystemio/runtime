const noop = () => {}

// The seam every app is written against. The app calls down (serveUI/emit/reportState); the host
// calls in (setState/command).
//
// Outbound traffic fans out to OBSERVERS rather than a single callback. More than one thing
// legitimately watches an app — the runner's own reset timer and the MCP link, at minimum — and a
// plain `ipc.onReport = …` from either one silently destroyed the other.
class IPC {
  constructor(ui, opts = {}) {
    this.ui = ui
    this.log = opts.log || noop
    this.media = opts.media || [] // media URLs found on disk, for the app to choose defaults from
    this.config = opts.config || {} // key/value from media/config.txt — secrets stay this side
    this.saved = opts.saved || {} // what the app last save()d, back after a restart
    this._download = opts.download || null
    this._save = opts.save || null
    this.caps = null
    this.state = null

    this._observers = []
    this._onUIMessage = noop
    this._onSetState = noop
    this._onCommand = noop

    ui.onMessage = (msg) => this._onUIMessage(msg)
  }

  // Watch an app without the app knowing. Returns an unobserve function.
  observe(handlers) {
    this._observers.push(handlers)
    return () => {
      const i = this._observers.indexOf(handlers)
      if (i !== -1) this._observers.splice(i, 1)
    }
  }

  _fanout(name, ...args) {
    for (const o of this._observers) {
      if (o[name]) o[name](...args)
    }
  }

  serveUI(html) {
    this.ui.setHtml(html)
  }
  sendUI(msg) {
    this.ui.broadcast(msg)
  }
  onUIMessage(fn) {
    this._onUIMessage = fn
  }

  describe(caps) {
    this.caps = caps
    this._fanout('onDescribe', caps)
  }

  emit(name, payload) {
    this.log('event ' + name + ' ' + JSON.stringify(payload ?? null))
    this._fanout('onEvent', name, payload)
  }

  reportState(state) {
    this.state = state
    this.log('state ' + JSON.stringify(state))
    this._fanout('onReport', state)
  }

  // Fetch a URL onto the device, once. Resolves to a /media/ URL the page can load like the card's
  // own art — it plays offline and after a reboot. onProgress gets { received, total } (total 0
  // when the server does not say). Apps have no filesystem, so the host does this for them.
  async download(url, onProgress) {
    if (!this._download) throw new Error('downloads need the runner')
    const at = await this._download(url, onProgress || noop)
    if (!this.media.includes(at)) this.media.push(at)
    return at
  }

  // A small JSON object the app wants back after a restart — which art a controller chose, say.
  save(obj) {
    this.saved = obj
    if (this._save) this._save(obj)
  }

  onSetState(fn) {
    this._onSetState = fn
  }
  onCommand(fn) {
    this._onCommand = fn
  }

  setState(phase) {
    this._onSetState(phase)
  }
  command(name, args) {
    return this._onCommand(name, args)
  }
}

module.exports = { IPC }
