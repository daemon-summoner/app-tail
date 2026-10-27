// SPDX-License-Identifier: MIT

import { useEffect, useMemo, useState } from 'react'
import {
  api,
  ApiError,
  type Direction,
  type Forward,
  type ForwardSpec,
  type Peer,
  type Preset,
  type Protocol,
  type TunnelView,
} from '../api'
import { Notice, Scrim } from './primitives'
import { isPort, parsePortSpec, splitHostPort } from '../lib/ports'
import { CloseIcon } from './shell/icons'

// MANUAL is the device dropdown's sentinel for "I'll type the host myself".
const MANUAL = '__manual__'

// Bind-address dropdown: the two interfaces almost everyone wants, plus a sentinel
// for binding one specific interface by IP. Any value that is neither preset is a
// typed IP, so the dropdown lands on "Specific IP" and reveals the text input.
const BIND_LOOPBACK = '127.0.0.1'
const BIND_ALL = '0.0.0.0'
const BIND_CUSTOM = '__bind_custom__'

/** A loopback bind is reachable from this machine only; anything else needs the user's
 *  explicit consent, which the agent also requires. */
function bindIsLoopback(addr: string): boolean {
  const a = addr.trim()
  return a.startsWith('127.') || a === '::1'
}

interface Draft {
  name: string
  // tunnelId is the connection this forward crosses. It decides which devices the picker
  // offers and which network the target name is resolved on.
  tunnelId: string
  direction: Direction
  protocol: Protocol
  // to_local device selection: pick a peer or type a host by hand.
  deviceMode: 'peer' | 'manual'
  peerHost: string
  // hostText is the manual host for to_local, or the local service host for to_tailnet.
  hostText: string
  // portsSpec names the service port(s): on the device for to_local, on this machine
  // for to_tailnet. It accepts one port, a range, or a comma/space-delimited list.
  portsSpec: string
  // listenOverride sets this side's listen port when it must differ from the service
  // port. It only applies to a single-port spec; a range always mirrors.
  listenOverride: string
  bindAddr: string
  // exposeToNetwork is the user's consent to a bind other machines can reach.
  exposeToNetwork: boolean
  udpTimeoutSec: string
}

function draftFrom(f: Forward): Draft {
  const { host, port } = splitHostPort(f.target)
  const hasPort = isPort(port)
  return {
    name: f.name,
    tunnelId: f.tunnelId,
    direction: f.direction,
    protocol: f.protocol,
    deviceMode: 'manual',
    peerHost: '',
    hostText: host,
    portsSpec: hasPort ? String(port) : '',
    // Show the listen port only when it differs from the service port; blank means "same".
    listenOverride: hasPort ? (f.listenPort === port ? '' : String(f.listenPort)) : String(f.listenPort),
    bindAddr: f.bindAddr || '127.0.0.1',
    exposeToNetwork: f.exposeToNetwork,
    udpTimeoutSec: f.udpTimeoutSec > 0 ? String(f.udpTimeoutSec) : '',
  }
}

const emptyDraft: Draft = {
  name: '',
  // Filled from the connection list as soon as it loads; blank until then means the form
  // has not yet been told which networks exist, not that a forward crosses none.
  tunnelId: '',
  direction: 'to_local',
  protocol: 'tcp',
  deviceMode: 'peer',
  peerHost: '',
  hostText: '',
  portsSpec: '',
  listenOverride: '',
  bindAddr: '127.0.0.1',
  exposeToNetwork: false,
  udpTimeoutSec: '',
}

/** peerHost is the address to target: the DNS name when there is one, since it
 *  survives the peer's IP changing. */
function peerHostOf(peer: Peer): string {
  return peer.dnsName || peer.ips[0] || peer.hostName
}

/** peerNote is the parenthetical after a device's name: what would stop a forward to it
 *  from working today. A ready device gets nothing, so the ones worth hesitating over
 *  are the ones that carry a word. It marks rather than disables -- a forward to a
 *  device that is currently down is a legitimate thing to set up ahead of time.
 *
 *  An agent too old to send a verdict still knows whether the device is online, which is
 *  the answer this dropdown gave before. */
function peerNote(peer: Peer): string {
  // Widened deliberately: the value arrives over the wire, so an agent newer than this
  // bundle can send a state this union does not list, and that must not read as healthy.
  const state: string = peer.reach?.state ?? (peer.online ? 'ready' : 'offline')
  switch (state) {
    case 'ready':
      return ''
    case 'relayed':
      return ' (relayed)'
    case 'no-path':
      return ' (unreachable)'
    case 'expired':
      return ' (key expired)'
    case 'offline':
      return ' (offline)'
    default:
      // A state this build does not know is still worth showing verbatim rather than
      // silently rendering as healthy.
      return ` (${state})`
  }
}

/** effectiveHost resolves the host a forward targets from whichever inputs the
 *  current direction and device mode expose. */
function effectiveHost(d: Draft): string {
  if (d.direction === 'to_tailnet') return d.hostText.trim() || '127.0.0.1'
  return (d.deviceMode === 'peer' ? d.peerHost : d.hostText).trim()
}

type Outcome = { port: number; ok: true } | { port: number; ok: false; message: string }

export function ForwardDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: Forward | undefined
  onClose: () => void
  onSaved: () => void
}) {
  const isEdit = editing !== undefined
  const [draft, setDraft] = useState<Draft>(editing ? draftFrom(editing) : emptyDraft)
  const [peers, setPeers] = useState<Peer[] | undefined>(undefined)
  const [tunnels, setTunnels] = useState<TunnelView[]>([])
  const [presets, setPresets] = useState<Preset[]>([])
  // The node's configured tags, used to mark which peers are part of this app-tail
  // fleet. Defaults to the built-in tag until settings load.
  const [fleetTags, setFleetTags] = useState<string[]>(['tag:app-tail'])
  const [error, setError] = useState<string | undefined>(undefined)
  const [conflictId, setConflictId] = useState<string | undefined>(undefined)
  const [saving, setSaving] = useState(false)

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((prev) => ({ ...prev, [key]: value }))

  // Escape closes, matching every other dialog the user has ever used.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Load the connection list so the form knows which networks a forward can cross. A
  // forward being edited keeps the connection it already names; a new one starts on the
  // first connection, which is the primary one on every install that has not added others.
  useEffect(() => {
    const ctrl = new AbortController()
    api
      .tunnels()
      .then((list) => {
        if (ctrl.signal.aborted) return
        setTunnels(list)
        setDraft((prev) =>
          prev.tunnelId !== '' || list[0] === undefined
            ? prev
            : { ...prev, tunnelId: list[0].id },
        )
      })
      .catch(() => {
        /* the picker is hidden without a list; the agent fills the connection in */
      })
    return () => ctrl.abort()
  }, [])

  // Load the chosen connection's device list. It is re-read whenever the connection
  // changes, because the devices on one network say nothing about the devices on another.
  // A network with none -- or one that is down -- falls back to manual entry so a forward
  // can still be created.
  useEffect(() => {
    if (draft.tunnelId === '') return
    const ctrl = new AbortController()
    api
      .tunnelPeers(draft.tunnelId)
      .then((list) => {
        if (ctrl.signal.aborted) return
        setPeers(list)
        if (list.length === 0 && !isEdit) setDraft((prev) => ({ ...prev, deviceMode: 'manual' }))
      })
      .catch(() => {
        if (ctrl.signal.aborted) return
        setPeers([])
        if (!isEdit) setDraft((prev) => ({ ...prev, deviceMode: 'manual' }))
      })
    return () => ctrl.abort()
  }, [draft.tunnelId, isEdit])

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .presets()
      .then((list) => {
        if (!ctrl.signal.aborted) setPresets(list)
      })
      .catch(() => {
        /* presets are a convenience; the form works without them */
      })
    return () => ctrl.abort()
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .settings()
      .then((s) => {
        if (!ctrl.signal.aborted && s.tags.length > 0) setFleetTags(s.tags)
      })
      .catch(() => {
        /* badging is a convenience; fall back to the default tag */
      })
    return () => ctrl.abort()
  }, [])

  const parsed = useMemo(() => parsePortSpec(draft.portsSpec), [draft.portsSpec])
  const isSinglePort = parsed.ports.length === 1
  const toLocal = draft.direction === 'to_local'

  // Peers carrying any of the node's tags are part of this app-tail fleet; surface
  // them in their own group so the user's other devices are set apart from them.
  const { fleetPeers, otherPeers } = useMemo(() => {
    const inFleet = (p: Peer) => (p.tags ?? []).some((t) => fleetTags.includes(t))
    const list = peers ?? []
    return { fleetPeers: list.filter(inFleet), otherPeers: list.filter((p) => !inFleet(p)) }
  }, [peers, fleetTags])

  const applyPreset = (id: string) => {
    const preset = presets.find((p) => p.id === id)
    if (!preset) return
    setDraft((prev) => ({
      ...prev,
      protocol: preset.protocol,
      portsSpec: String(preset.remotePort),
    }))
  }

  // buildSpec assembles one forward for service port p. For a single-port spec the
  // listen side may be overridden; a multi-port spec always mirrors p.
  const buildSpec = (host: string, p: number, single: boolean, override: string): ForwardSpec => {
    const listen = single && override !== '' ? Number(override) : p
    const spec: ForwardSpec = {
      name: parsed.ports.length > 1 ? (draft.name.trim() ? `${draft.name.trim()} ${p}` : '') : draft.name.trim(),
      direction: draft.direction,
      protocol: draft.protocol,
      listenPort: listen,
      ...(draft.tunnelId === '' ? {} : { tunnelId: draft.tunnelId }),
      target: `${host}:${p}`,
      udpTimeoutSec: draft.udpTimeoutSec.trim() === '' ? 0 : Number(draft.udpTimeoutSec),
    }
    if (toLocal) {
      spec.bindAddr = draft.bindAddr.trim()
      spec.exposeToNetwork = !bindIsLoopback(spec.bindAddr) && draft.exposeToNetwork
    }
    return spec
  }

  const validate = (host: string, override: string): string | undefined => {
    if (parsed.error) return parsed.error
    if (parsed.ports.length === 0) return 'Enter at least one port.'
    if (host === '') return toLocal ? 'Choose a device or enter a host.' : 'Enter the local service host.'
    if (override !== '' && !isPort(Number(override))) return 'The listen port override must be 1-65535.'
    // A blank bind address only reaches here when "Specific IP" is chosen but nothing
    // is typed; a malformed IP is left to the backend, which names it in a 400.
    if (toLocal && draft.bindAddr.trim() === '')
      return 'Enter an IP for the specific interface, or pick Loopback or All interfaces.'
    if (toLocal && !bindIsLoopback(draft.bindAddr) && !draft.exposeToNetwork)
      return 'Tick "Let other machines on your network use this forward" to bind beyond this machine, or pick Loopback.'
    return undefined
  }

  const saveEdit = async (host: string, override: string) => {
    const p = parsed.ports[0]
    if (p === undefined) return // validate() already guaranteed one port; this narrows the type
    const listen = override !== '' ? Number(override) : p
    const spec: ForwardSpec = {
      name: draft.name.trim(),
      direction: draft.direction,
      protocol: draft.protocol,
      listenPort: listen,
      ...(draft.tunnelId === '' ? {} : { tunnelId: draft.tunnelId }),
      target: `${host}:${p}`,
      udpTimeoutSec: draft.udpTimeoutSec.trim() === '' ? 0 : Number(draft.udpTimeoutSec),
    }
    if (toLocal) {
      spec.bindAddr = draft.bindAddr.trim()
      spec.exposeToNetwork = !bindIsLoopback(spec.bindAddr) && draft.exposeToNetwork
    }
    await api.updateForward(editing!.id, spec)
    onSaved()
    onClose()
  }

  const saveCreate = async (host: string, override: string) => {
    const single = parsed.ports.length === 1
    const results: Outcome[] = []
    for (const p of parsed.ports) {
      const spec = buildSpec(host, p, single, override)
      // For a lone to_local forward with no explicit listen port, ask the agent for a
      // bindable one so a service already using that number locally is dodged. A range
      // mirrors instead, so its ports stay predictable.
      if (single && toLocal && override === '') {
        try {
          spec.listenPort = await api.suggestPort(draft.protocol, `${host}:${p}`, draft.bindAddr.trim())
        } catch {
          /* a suggestion is a convenience; fall back to the mirrored port */
        }
      }
      try {
        await api.createForward(spec)
        results.push({ port: p, ok: true })
      } catch (cause) {
        results.push({
          port: p,
          ok: false,
          message: cause instanceof ApiError ? cause.message : String(cause),
        })
      }
    }

    const failures = results.filter((r): r is Extract<Outcome, { ok: false }> => !r.ok)
    onSaved()
    if (failures.length === 0) {
      onClose()
      return
    }
    const created = results.length - failures.length
    setError(
      (created > 0 ? `Created ${created} forward${created === 1 ? '' : 's'}. ` : '') +
        `Could not add ${failures.length}: ` +
        failures.map((f) => `port ${f.port} (${f.message})`).join('; '),
    )
  }

  const save = async () => {
    const host = effectiveHost(draft)
    const override = draft.listenOverride.trim()
    const problem = validate(host, override)
    if (problem) {
      setError(problem)
      return
    }

    setSaving(true)
    setError(undefined)
    setConflictId(undefined)
    try {
      if (isEdit) {
        await saveEdit(host, override)
      } else {
        await saveCreate(host, override)
      }
    } catch (cause) {
      if (cause instanceof ApiError) {
        setError(cause.message)
        setConflictId(cause.conflict?.forwardId)
      } else {
        setError(String(cause))
      }
    } finally {
      setSaving(false)
    }
  }

  const overrideLabel = toLocal ? 'Local port' : 'Tailnet port'
  const portsLabel = toLocal ? 'Port(s) on the device' : 'Port(s) to expose'
  const carriesUDP = draft.protocol === 'udp' || draft.protocol === 'both'
  const bindIsCustom = draft.bindAddr !== BIND_LOOPBACK && draft.bindAddr !== BIND_ALL

  return (
    <Scrim onClose={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={isEdit ? 'Edit forward' : 'Add forward'}
      >
        <div className="overlay-head">
          <h2>{isEdit ? 'Edit forward' : 'Add forward'}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          {error ? (
            <Notice tone="error">
              {error}
              {conflictId ? ` (conflicting forward: ${conflictId})` : ''}
            </Notice>
          ) : null}

          <div className="form-grid">
            <div className="field span-2">
              <label htmlFor="fwd-name">Name {isEdit ? '' : '(optional)'}</label>
              <input
                id="fwd-name"
                type="text"
                value={draft.name}
                placeholder={isEdit ? '' : 'auto-named from the service if left blank'}
                onChange={(e) => set('name', e.target.value)}
              />
              <span className="hint">
                Only a label. With several ports, each forward gets its port appended.
              </span>
            </div>

            {tunnels.length > 1 ? (
              <div className="field span-2">
                <label htmlFor="fwd-connection">Connection</label>
                <select
                  id="fwd-connection"
                  value={draft.tunnelId}
                  onChange={(e) => {
                    // The devices belong to the connection that was selected, so both the
                    // list and anything chosen from it describe the previous network and
                    // are cleared here rather than left on screen until the next one loads.
                    setPeers(undefined)
                    setDraft((prev) => ({
                      ...prev,
                      tunnelId: e.target.value,
                      deviceMode: 'peer',
                      peerHost: '',
                    }))
                  }}
                >
                  {tunnels.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} — {t.typeLabel}
                      {t.live ? '' : ' (not connected)'}
                    </option>
                  ))}
                </select>
                <span className="hint">
                  Which network this forward crosses. Devices and addresses are resolved on it.
                </span>
              </div>
            ) : null}

            <div className="field">
              <label htmlFor="fwd-direction">Direction</label>
              <select
                id="fwd-direction"
                value={draft.direction}
                onChange={(e) => set('direction', e.target.value as Direction)}
              >
                <option value="to_local">to local — reach a device on the tailnet</option>
                <option value="to_tailnet">to tailnet — expose a local service</option>
              </select>
              {!toLocal ? (
                <span className="hint">
                  Every device your ACLs allow will be able to reach this service.
                </span>
              ) : null}
            </div>

            <div className="field">
              <label htmlFor="fwd-protocol">Protocol</label>
              <select
                id="fwd-protocol"
                value={draft.protocol}
                onChange={(e) => set('protocol', e.target.value as Protocol)}
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">Both (TCP + UDP)</option>
              </select>
              <span className="hint">
                Most services are TCP-only. Both runs one rule on each transport, for services like
                DNS.
              </span>
            </div>

            {presets.length > 0 ? (
              <div className="field span-2">
                <label htmlFor="fwd-preset">Common service (optional)</label>
                <select
                  id="fwd-preset"
                  value=""
                  onChange={(e) => {
                    applyPreset(e.target.value)
                    e.currentTarget.selectedIndex = 0
                  }}
                >
                  <option value="">Pick to fill protocol and port…</option>
                  {presets.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} — {p.protocol.toUpperCase()} {p.remotePort}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {toLocal ? (
              <div className="field span-2">
                <label htmlFor="fwd-device">Device</label>
                <select
                  id="fwd-device"
                  value={draft.deviceMode === 'manual' ? MANUAL : draft.peerHost}
                  onChange={(e) => {
                    const v = e.target.value
                    if (v === MANUAL) set('deviceMode', 'manual')
                    else setDraft((prev) => ({ ...prev, deviceMode: 'peer', peerHost: v }))
                  }}
                >
                  {peers === undefined ? (
                    <option value="">Loading devices…</option>
                  ) : (
                    <option value="" disabled>
                      {peers.length === 0 ? 'No devices found' : 'Select a device…'}
                    </option>
                  )}
                  {fleetPeers.length > 0 ? (
                    <>
                      <optgroup label="app-tail devices">
                        {fleetPeers.map((p) => (
                          <option key={p.id} value={peerHostOf(p)}>
                            {p.hostName}
                            {peerNote(p)} — {peerHostOf(p)} · app-tail
                          </option>
                        ))}
                      </optgroup>
                      {otherPeers.length > 0 ? (
                        <optgroup label="Other devices">
                          {otherPeers.map((p) => (
                            <option key={p.id} value={peerHostOf(p)}>
                              {p.hostName}
                              {peerNote(p)} — {peerHostOf(p)}
                            </option>
                          ))}
                        </optgroup>
                      ) : null}
                    </>
                  ) : (
                    (peers ?? []).map((p) => (
                      <option key={p.id} value={peerHostOf(p)}>
                        {p.hostName}
                        {peerNote(p)} — {peerHostOf(p)}
                      </option>
                    ))
                  )}
                  <option value={MANUAL}>Enter a host manually…</option>
                </select>
                {draft.deviceMode === 'manual' ? (
                  <input
                    type="text"
                    aria-label="Host"
                    value={draft.hostText}
                    placeholder="100.64.0.5, gpu-box.tail1234.ts.net, or a LAN address"
                    onChange={(e) => set('hostText', e.target.value)}
                  />
                ) : null}
                <span className="hint">
                  Devices with a DNS name are targeted by name, so the forward survives their IP
                  changing.
                </span>
              </div>
            ) : (
              <div className="field span-2">
                <label htmlFor="fwd-localhost">Local service host</label>
                <input
                  id="fwd-localhost"
                  type="text"
                  value={draft.hostText}
                  placeholder="127.0.0.1"
                  onChange={(e) => set('hostText', e.target.value)}
                />
                <span className="hint">The address of the service on this machine to publish.</span>
              </div>
            )}

            <div className={isSinglePort ? 'field' : 'field span-2'}>
              <label htmlFor="fwd-ports">{portsLabel}</label>
              <input
                id="fwd-ports"
                type="text"
                inputMode="numeric"
                value={draft.portsSpec}
                placeholder="8100, 9000-9005"
                onChange={(e) => set('portsSpec', e.target.value)}
              />
              {parsed.error && draft.portsSpec.trim() !== '' ? (
                <span className="hint bad">{parsed.error}</span>
              ) : parsed.ports.length > 1 ? (
                <span className="hint ok">Creates {parsed.ports.length} forwards, one per port.</span>
              ) : (
                <span className="hint">One port, a range like 9000-9005, or a comma-separated list.</span>
              )}
            </div>

            {isSinglePort ? (
              <div className="field">
                <label htmlFor="fwd-listen">{overrideLabel}</label>
                <input
                  id="fwd-listen"
                  type="number"
                  min={1}
                  max={65535}
                  value={draft.listenOverride}
                  placeholder={`same (${parsed.ports[0]})`}
                  onChange={(e) => set('listenOverride', e.target.value)}
                />
                <span className="hint">
                  {toLocal
                    ? 'Local port to listen on. Blank picks a free one near the service port.'
                    : 'Tailnet port to publish on. Blank uses the same number.'}
                </span>
              </div>
            ) : null}

            {toLocal ? (
              <div className="field span-2">
                <label htmlFor="fwd-bind">Bind address</label>
                <select
                  id="fwd-bind"
                  value={bindIsCustom ? BIND_CUSTOM : draft.bindAddr}
                  onChange={(e) => {
                    const v = e.target.value
                    // Switching to "Specific IP" clears the field for a fresh entry, but only
                    // when leaving a preset, so re-selecting it never wipes a typed address.
                    if (v === BIND_CUSTOM) {
                      if (!bindIsCustom) set('bindAddr', '')
                    } else set('bindAddr', v)
                  }}
                >
                  <option value={BIND_LOOPBACK}>Loopback (127.0.0.1) — this machine only</option>
                  <option value={BIND_ALL}>All interfaces (0.0.0.0) — reachable on your LAN</option>
                  <option value={BIND_CUSTOM}>Specific IP…</option>
                </select>
                {bindIsCustom ? (
                  <input
                    type="text"
                    aria-label="Bind IP address"
                    value={draft.bindAddr}
                    placeholder="e.g. 192.168.1.50"
                    onChange={(e) => set('bindAddr', e.target.value)}
                  />
                ) : null}
                <span className="hint">
                  {draft.bindAddr === BIND_LOOPBACK
                    ? 'Only this machine can reach the forward.'
                    : draft.bindAddr === BIND_ALL
                      ? "Any device on your local network can reach it at this machine's LAN IP."
                      : 'Binds only the network interface that owns this IP.'}
                </span>
                {bindIsLoopback(draft.bindAddr) ? null : (
                  <div className="choice-set">
                    <label className="choice">
                      <input
                        type="checkbox"
                        aria-label="Let other machines on your network use this forward"
                        checked={draft.exposeToNetwork}
                        onChange={(e) => set('exposeToNetwork', e.target.checked)}
                      />
                      <span className="choice-text">
                        <span className="choice-label">Let other machines on your network use this forward</span>
                        <span className="hint">
                          Anyone who can reach this machine can use it, with no password.
                        </span>
                      </span>
                    </label>
                  </div>
                )}
              </div>
            ) : null}

            {carriesUDP ? (
              <div className="field span-2">
                <label htmlFor="fwd-udp-timeout">UDP session timeout (seconds)</label>
                <input
                  id="fwd-udp-timeout"
                  type="number"
                  min={0}
                  value={draft.udpTimeoutSec}
                  placeholder="use the global default"
                  onChange={(e) => set('udpTimeoutSec', e.target.value)}
                />
                <span className="hint">
                  UDP has no close, so idle sessions are evicted after this long. Leave empty to use
                  the global setting.
                </span>
              </div>
            ) : null}
          </div>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={saving} onClick={() => void save()}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create forward'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
