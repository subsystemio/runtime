const Protomux = require('protomux')
const protocol = require('./protocol.js')

// Two hops, two channel sets. Message indices are positional, so BOTH ends must addMessage in the
// SAME order on the SAME channel. Each side passes only the handlers it cares about; unhandled
// inbound messages are dropped.

// MCP <-> subsystem. The subsystem announces; the MCP dials it.
// handlers: onCapability, onAttestation, onDescribe, onEvent, onStateReport, onCommandResult, onCommand
function createChannels(stream, handlers = {}) {
  const mux = Protomux.from(stream)

  // Optional room membership. Authority is the peer's public key either way — this only hides the
  // fleet from someone who has learned the topic. See lib/room.js.
  const auth = mux.createChannel({ protocol: 'subsystem/auth' })
  const capabilityMsg = auth.addMessage({
    encoding: protocol.capability,
    onmessage: handlers.onCapability
  })
  const attestationMsg = auth.addMessage({
    encoding: protocol.attestation,
    onmessage: handlers.onAttestation
  })
  auth.open()

  const events = mux.createChannel({ protocol: 'subsystem/events' })
  const describeMsg = events.addMessage({
    encoding: protocol.describe,
    onmessage: handlers.onDescribe
  })
  const eventMsg = events.addMessage({ encoding: protocol.event, onmessage: handlers.onEvent })
  const stateReportMsg = events.addMessage({
    encoding: protocol.stateReport,
    onmessage: handlers.onStateReport
  })
  const commandResultMsg = events.addMessage({
    encoding: protocol.commandResult,
    onmessage: handlers.onCommandResult
  })
  events.open()

  const control = mux.createChannel({ protocol: 'subsystem/control' })
  const commandMsg = control.addMessage({
    encoding: protocol.command,
    onmessage: handlers.onCommand
  })
  control.open()

  return {
    mux,
    sendCapability: (m) => capabilityMsg.send(m),
    sendAttestation: (m) => attestationMsg.send(m),
    sendDescribe: (m) => describeMsg.send(m),
    sendEvent: (m) => eventMsg.send(m),
    sendStateReport: (m) => stateReportMsg.send(m),
    sendCommandResult: (m) => commandResultMsg.send(m),
    sendCommand: (m) => commandMsg.send(m)
  }
}

// MCP <-> operator. The MCP listens on its own key; operators dial it. No shared secret on this
// hop — the roster decides, and the Noise handshake proves who is asking.
// handlers: onOperatorHello, onSubsystem, onState, onEvent, onInvoke, onResult, onAdopt, onOperator,
// onRole
function createFleetChannels(stream, handlers = {}) {
  const mux = Protomux.from(stream)

  const fleet = mux.createChannel({ protocol: 'mcp/fleet' })
  // The operator proves which identity it is before the MCP decides what it may do. Unlike the
  // device hop this is not checked against an expected identity — anyone may present one — it only
  // binds this connection to an identity so the roster can be consulted. Trust is the roster's.
  const attestationMsg = fleet.addMessage({
    encoding: protocol.attestation,
    onmessage: handlers.onAttestation
  })
  const helloMsg = fleet.addMessage({
    encoding: protocol.operatorHello,
    onmessage: handlers.onOperatorHello
  })
  const subsystemMsg = fleet.addMessage({
    encoding: protocol.fleetSubsystem,
    onmessage: handlers.onSubsystem
  })
  const stateMsg = fleet.addMessage({ encoding: protocol.fleetState, onmessage: handlers.onState })
  const eventMsg = fleet.addMessage({ encoding: protocol.fleetEvent, onmessage: handlers.onEvent })
  const invokeMsg = fleet.addMessage({
    encoding: protocol.fleetInvoke,
    onmessage: handlers.onInvoke
  })
  const resultMsg = fleet.addMessage({
    encoding: protocol.fleetResult,
    onmessage: handlers.onResult
  })
  const adoptMsg = fleet.addMessage({ encoding: protocol.fleetAdopt, onmessage: handlers.onAdopt })
  // Last, always: messages are numbered by the order they are added, so a new one goes on the end
  // or every message after it changes meaning between versions.
  const operatorMsg = fleet.addMessage({
    encoding: protocol.fleetOperator,
    onmessage: handlers.onOperator
  })
  const roleMsg = fleet.addMessage({ encoding: protocol.fleetRole, onmessage: handlers.onRole })
  fleet.open()

  return {
    mux,
    sendAttestation: (m) => attestationMsg.send(m),
    sendOperatorHello: (m) => helloMsg.send(m),
    sendSubsystem: (m) => subsystemMsg.send(m),
    sendState: (m) => stateMsg.send(m),
    sendEvent: (m) => eventMsg.send(m),
    sendInvoke: (m) => invokeMsg.send(m),
    sendResult: (m) => resultMsg.send(m),
    sendAdopt: (m) => adoptMsg.send(m),
    sendOperator: (m) => operatorMsg.send(m),
    sendRole: (m) => roleMsg.send(m)
  }
}

module.exports = { createChannels, createFleetChannels }
