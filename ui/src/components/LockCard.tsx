// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type LockUpdate, type LockView } from '../api'
import { Panel } from './Panel'
import { CodeBlock, Notice } from './primitives'

/** The state the device is in, as one word plus the colour that goes with it. A device
 *  lock has not signed reads as an error rather than a warning: it can reach nothing at
 *  all, which is the same outcome as a node that never connected. */
function lockState(view: LockView): { tone: string; label: string } {
  if (!view.capability.available) return { tone: 'off', label: 'unknown' }
  if (!view.enabled) return { tone: 'running', label: 'off for this tailnet' }
  if (!view.signed) return { tone: 'error', label: 'this device is not signed' }
  if (view.capability.degraded) return { tone: 'pending', label: 'some devices held back' }
  return { tone: 'running', label: 'signed' }
}

/** The devices lock removed from this one's view of the tailnet. Named rather than
 *  counted, because the user has to go and look at those specific devices. */
function HeldBack({ view }: { view: LockView }) {
  const filtered = view.filtered ?? []
  if (filtered.length === 0) return null
  return (
    <div className="lock-filtered">
      <h3>Held back by tailnet lock</h3>
      <p className="hint">
        These devices are on your tailnet and this one cannot reach them, however your
        access rules read. They are waiting to be signed too.
      </p>
      <ul>
        {filtered.map((peer) => (
          <li key={peer.id}>
            <span>{peer.name}</span>
            <span className="mono">{peer.nodeKey}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function TrustedKeys({ view }: { view: LockView }) {
  const trusted = view.trusted ?? []
  if (trusted.length === 0) return null
  return (
    <div className="lock-keys">
      <h3>Keys your tailnet trusts</h3>
      <ul>
        {trusted.map((key) => (
          <li key={key.id}>
            <span className="mono">{key.id}</span>
            {key.label ? <span className="hint">{key.label}</span> : null}
            {key.self ? <span className="badge">this device</span> : null}
          </li>
        ))}
      </ul>
    </div>
  )
}

function History({ entries }: { entries: LockUpdate[] }) {
  if (entries.length === 0) {
    return <Notice tone="info">Your tailnet&rsquo;s key authority has no recorded changes.</Notice>
  }
  return (
    <ul className="lock-log">
      {entries.map((entry) => (
        <li key={entry.hash}>
          <span className="mono">{entry.hash.slice(0, 12)}</span>
          <span>{entry.change}</span>
        </li>
      ))}
    </ul>
  )
}

/** Signing another device is offered only to a device holding a trusted key, because it
 *  is the only one whose signature the tailnet accepts. Showing the form to everyone else
 *  would produce a refusal from the backend that reads as a broken feature. */
function SignForm({ onSigned }: { onSigned: () => void }) {
  const [nodeKey, setNodeKey] = useState('')
  const [rotationKey, setRotationKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [done, setDone] = useState<string | undefined>(undefined)

  const submit = async () => {
    setBusy(true)
    setError(undefined)
    setDone(undefined)
    try {
      await api.signForLock(nodeKey.trim(), rotationKey.trim())
      setDone(`Signed ${nodeKey.trim()}.`)
      setNodeKey('')
      setRotationKey('')
      onSigned()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="lock-sign">
      <h3>Authorize another device</h3>
      <p className="hint">
        Paste the keys the locked-out device reports. The tailnet lock key is optional; it
        is what lets that device re-sign itself after a key rotation.
      </p>
      {/* The prefixes are in the labels rather than greyed inside the boxes: a device
          reports several keys and pasting the wrong one is the mistake to prevent, so the
          shape has to be readable while a value is already typed. */}
      <label>
        Device node key, starting nodekey:
        <input value={nodeKey} onChange={(e) => setNodeKey(e.target.value)} />
      </label>
      <label>
        Device tailnet lock key, starting tlpub: (optional)
        <input value={rotationKey} onChange={(e) => setRotationKey(e.target.value)} />
      </label>
      <button
        className="btn small"
        disabled={busy || nodeKey.trim() === ''}
        onClick={() => void submit()}
      >
        {busy ? 'Signing…' : 'Sign this device'}
      </button>
      {error ? <Notice tone="error">{error}</Notice> : null}
      {done ? <Notice tone="info">{done}</Notice> : null}
    </div>
  )
}

export function LockCard({ view, onChanged }: { view: LockView; onChanged: () => void }) {
  const [log, setLog] = useState<LockUpdate[] | undefined>(undefined)
  const [loadingLog, setLoadingLog] = useState(false)
  const [logError, setLogError] = useState<string | undefined>(undefined)

  const loadLog = async () => {
    setLoadingLog(true)
    setLogError(undefined)
    try {
      setLog(await api.lockLog())
    } catch (cause) {
      setLogError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setLoadingLog(false)
    }
  }

  const state = lockState(view)

  return (
    <Panel
      title="Tailnet lock"
      status={{ tone: state.tone, label: state.label }}
      info={
        <p>
          Your tailnet requires every device to be signed by a trusted key before others
          will talk to it. A device waiting to be signed connects, reports itself running,
          and reaches nothing — which is exactly what this card exists to name.
        </p>
      }
      actions={
        <button className="btn ghost small" disabled={loadingLog} onClick={() => void loadLog()}>
          {loadingLog ? 'Loading…' : 'Show history'}
        </button>
      }
    >
      {view.capability.reason ? (
          <Notice tone={view.signed || !view.enabled ? 'info' : 'error'}>
            {view.capability.reason}
          </Notice>
        ) : null}

        {/* The command is the entire remedy, and it is what a locked-out user came here
            for. It comes from the agent, so what is copied is what was built from this
            device's own keys rather than something assembled in the browser. */}
        {!view.signed && view.signCommand ? (
          <>
            <p className="hint">
              Run this on any device that holds a trusted key, then this one reconnects on
              its own.
            </p>
            <CodeBlock text={view.signCommand} />
          </>
        ) : null}

        <HeldBack view={view} />
        <TrustedKeys view={view} />

        {view.canSign ? <SignForm onSigned={onChanged} /> : null}

        {/* A failed read is the reason the module is degraded, so the agent puts it in
            both places. Printing it twice reads as two separate faults. */}
        {view.error && view.error !== view.capability.reason ? (
          <Notice tone="error">{view.error}</Notice>
        ) : null}
      {logError ? <Notice tone="error">{logError}</Notice> : null}
      {log ? <History entries={log} /> : null}
    </Panel>
  )
}
