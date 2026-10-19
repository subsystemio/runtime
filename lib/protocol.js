const cenc = require('compact-encoding')

// PLATFORM protocol — fixed and app-AGNOSTIC. These are the only messages the platform ever
// interprets. App behaviour is never baked in here: an app ships a declarative capability manifest
// (`describe`) and the controller monitors and drives any app generically from it. Adding a new app
// touches none of this.
//
// Apps are delivered by flashing an SD card, not over the wire, so there is no content channel and
// no bundle versioning. The controller observes and commands; it does not deploy.
//
// Fields are positional. Nothing has shipped yet, so this format is still free to change however it
// needs to — reorder, retype, delete a whole message. The moment a card is in a venue that stops:
// from then on new fields append at the END and existing ones are never removed or reordered,
// because a device in the field cannot be updated over the wire.

// capability { proof } — hyperswarm-capability proof of the room secret, bound to this stream's
// Noise handshake hash. Exchanged before anything else; nothing on the other channels is sent or
// acted on until it verifies, so a peer outside the room learns nothing — not even that a subsystem
// exists. The secret itself never crosses the wire and the proof cannot be replayed elsewhere.
const capability = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.proof)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.proof)
  },
  decode(state) {
    return { proof: cenc.fixed32.decode(state) }
  }
}

// attestation { proof } — the MCP proves its device key was attested by the root identity whose
// PUBLIC key is on our card. One-directional: subsystems are trusted by the MCP's roster, not by a
// proof, so they never send one. See lib/attest.js for what must hold.
const attestation = {
  preencode(state, m) {
    cenc.buffer.preencode(state, m.proof)
  },
  encode(state, m) {
    cenc.buffer.encode(state, m.proof)
  },
  decode(state) {
    return { proof: cenc.buffer.decode(state) }
  }
}

// describe { appId, appVersion, caps } — the app's self-description. `caps` is a JSON string:
// { id, commands:[{name,args?}], events:[{name}], state:[{name,type}] }. The controller renders and
// drives the subsystem from this alone, so it needs no app-specific code.
const describe = {
  preencode(state, m) {
    cenc.string.preencode(state, m.appId)
    cenc.string.preencode(state, m.appVersion)
    cenc.string.preencode(state, m.caps)
  },
  encode(state, m) {
    cenc.string.encode(state, m.appId)
    cenc.string.encode(state, m.appVersion)
    cenc.string.encode(state, m.caps)
  },
  decode(state) {
    return {
      appId: cenc.string.decode(state),
      appVersion: cenc.string.decode(state),
      caps: cenc.string.decode(state)
    }
  }
}

// event { name, payload(JSON), ts } — generic telemetry (solved/input/tamper/custom).
const event = {
  preencode(state, m) {
    cenc.string.preencode(state, m.name)
    cenc.string.preencode(state, m.payload)
    cenc.uint.preencode(state, m.ts)
  },
  encode(state, m) {
    cenc.string.encode(state, m.name)
    cenc.string.encode(state, m.payload)
    cenc.uint.encode(state, m.ts)
  },
  decode(state) {
    return {
      name: cenc.string.decode(state),
      payload: cenc.string.decode(state),
      ts: cenc.uint.decode(state)
    }
  }
}

// state-report { state(JSON), ts } — current app state snapshot. Idempotent.
//
// The platform reserves no field NAMES. How each field is drawn, and what it means, come from the
// app's own `describe().state`: `display` ('tick' | 'badge' | 'count' | 'text' | 'progress' |
// 'hidden') and an optional `role`. `role: 'terminal'` marks the flag that says this subsystem has
// finished — which is how a console can summarise a whole room without understanding any single app.
// A 'progress' value is { what, received, total } (total 0 when unknown), and is left out of the
// state entirely when nothing is in flight.
const stateReport = {
  preencode(state, m) {
    cenc.string.preencode(state, m.state)
    cenc.uint.preencode(state, m.ts)
  },
  encode(state, m) {
    cenc.string.encode(state, m.state)
    cenc.uint.encode(state, m.ts)
  },
  decode(state) {
    return { state: cenc.string.decode(state), ts: cenc.uint.decode(state) }
  }
}

// command-result { id, ok, result(JSON) } — reply to a command, correlated by id.
const commandResult = {
  preencode(state, m) {
    cenc.uint.preencode(state, m.id)
    cenc.bool.preencode(state, m.ok)
    cenc.string.preencode(state, m.result)
  },
  encode(state, m) {
    cenc.uint.encode(state, m.id)
    cenc.bool.encode(state, m.ok)
    cenc.string.encode(state, m.result)
  },
  decode(state) {
    return {
      id: cenc.uint.decode(state),
      ok: cenc.bool.decode(state),
      result: cenc.string.decode(state)
    }
  }
}

// command { id, name, args(JSON) } — invoke a command the app declared in `describe`. The platform
// does not know what `name` means; the app's onCommand handler does.
const command = {
  preencode(state, m) {
    cenc.uint.preencode(state, m.id)
    cenc.string.preencode(state, m.name)
    cenc.string.preencode(state, m.args)
  },
  encode(state, m) {
    cenc.uint.encode(state, m.id)
    cenc.string.encode(state, m.name)
    cenc.string.encode(state, m.args)
  },
  decode(state) {
    return {
      id: cenc.uint.decode(state),
      name: cenc.string.decode(state),
      args: cenc.string.decode(state)
    }
  }
}

// ── fleet channel: MCP <-> operator ────────────────────────────────────────
//
// The device hop above is one subsystem talking about itself. This hop is the MCP talking about
// ALL of them, so every message is addressed by the subsystem's public key. Same shapes, one extra
// field — an operator console is the device console with a `key` column.

// operator-hello { role } — 'admin' | 'user' | 'pending'. The MCP tells a console what it is allowed
// to do, so the UI can say so up front rather than letting an operator press keys that will be
// refused. Sent again whenever an admin changes it.
const operatorHello = {
  preencode(state, m) {
    cenc.string.preencode(state, m.role)
  },
  encode(state, m) {
    cenc.string.encode(state, m.role)
  },
  decode(state) {
    return { role: cenc.string.decode(state) }
  }
}

// fleet-subsystem { key, adopted, online, appId, appVersion, caps } — one entry in the roster.
// `adopted` is the trust decision: an unadopted subsystem is shown but never believed.
const fleetSubsystem = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.bool.preencode(state, m.adopted)
    cenc.bool.preencode(state, m.online)
    cenc.string.preencode(state, m.appId)
    cenc.string.preencode(state, m.appVersion)
    cenc.string.preencode(state, m.caps)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.bool.encode(state, m.adopted)
    cenc.bool.encode(state, m.online)
    cenc.string.encode(state, m.appId)
    cenc.string.encode(state, m.appVersion)
    cenc.string.encode(state, m.caps)
  },
  decode(state) {
    return {
      key: cenc.fixed32.decode(state),
      adopted: cenc.bool.decode(state),
      online: cenc.bool.decode(state),
      appId: cenc.string.decode(state),
      appVersion: cenc.string.decode(state),
      caps: cenc.string.decode(state)
    }
  }
}

const fleetState = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.string.preencode(state, m.state)
    cenc.uint.preencode(state, m.ts)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.string.encode(state, m.state)
    cenc.uint.encode(state, m.ts)
  },
  decode(state) {
    return {
      key: cenc.fixed32.decode(state),
      state: cenc.string.decode(state),
      ts: cenc.uint.decode(state)
    }
  }
}

const fleetEvent = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.string.preencode(state, m.name)
    cenc.string.preencode(state, m.payload)
    cenc.uint.preencode(state, m.ts)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.string.encode(state, m.name)
    cenc.string.encode(state, m.payload)
    cenc.uint.encode(state, m.ts)
  },
  decode(state) {
    return {
      key: cenc.fixed32.decode(state),
      name: cenc.string.decode(state),
      payload: cenc.string.decode(state),
      ts: cenc.uint.decode(state)
    }
  }
}

// fleet-invoke { id, key, name, args } — operator asks the MCP to run a command on one subsystem.
const fleetInvoke = {
  preencode(state, m) {
    cenc.uint.preencode(state, m.id)
    cenc.fixed32.preencode(state, m.key)
    cenc.string.preencode(state, m.name)
    cenc.string.preencode(state, m.args)
  },
  encode(state, m) {
    cenc.uint.encode(state, m.id)
    cenc.fixed32.encode(state, m.key)
    cenc.string.encode(state, m.name)
    cenc.string.encode(state, m.args)
  },
  decode(state) {
    return {
      id: cenc.uint.decode(state),
      key: cenc.fixed32.decode(state),
      name: cenc.string.decode(state),
      args: cenc.string.decode(state)
    }
  }
}

const fleetResult = {
  preencode(state, m) {
    cenc.uint.preencode(state, m.id)
    cenc.bool.preencode(state, m.ok)
    cenc.string.preencode(state, m.result)
  },
  encode(state, m) {
    cenc.uint.encode(state, m.id)
    cenc.bool.encode(state, m.ok)
    cenc.string.encode(state, m.result)
  },
  decode(state) {
    return {
      id: cenc.uint.decode(state),
      ok: cenc.bool.decode(state),
      result: cenc.string.decode(state)
    }
  }
}

// fleet-adopt { key, adopt } — an admin deciding whether to trust a subsystem or an operator.
const fleetAdopt = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.bool.preencode(state, m.adopt)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.bool.encode(state, m.adopt)
  },
  decode(state) {
    return { key: cenc.fixed32.decode(state), adopt: cenc.bool.decode(state) }
  }
}

// fleet-operator { key, role, online } — MCP -> admins: an operator identity it knows of, so one can
// be approved from a console. `key` is the IDENTITY, not a machine. A phone mints its own identity
// and arrives `pending`; an admin answers with fleet-adopt. Sent to admins only.
const fleetOperator = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.string.preencode(state, m.role)
    cenc.bool.preencode(state, m.online)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.string.encode(state, m.role)
    cenc.bool.encode(state, m.online)
  },
  decode(state) {
    return {
      key: cenc.fixed32.decode(state),
      role: cenc.string.decode(state),
      online: cenc.bool.decode(state)
    }
  }
}

// fleet-role { key, role } — admin -> MCP: what an operator identity may do. 'admin' runs commands and
// decides who is trusted; 'user' runs commands only; 'pending' watches. fleet-adopt stays for props.
const fleetRole = {
  preencode(state, m) {
    cenc.fixed32.preencode(state, m.key)
    cenc.string.preencode(state, m.role)
  },
  encode(state, m) {
    cenc.fixed32.encode(state, m.key)
    cenc.string.encode(state, m.role)
  },
  decode(state) {
    return { key: cenc.fixed32.decode(state), role: cenc.string.decode(state) }
  }
}

module.exports = {
  // both, first
  capability,
  attestation,
  // subsystem -> ctrl
  describe,
  event,
  stateReport,
  commandResult,
  // ctrl -> subsystem
  command,
  // MCP <-> operator
  operatorHello,
  fleetSubsystem,
  fleetState,
  fleetEvent,
  fleetInvoke,
  fleetResult,
  fleetAdopt,
  fleetOperator,
  fleetRole
}
