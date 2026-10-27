// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { api, ApiError, type Preset, type Protocol } from '../api'
import { isPort } from '../lib/ports'
import { Notice } from './primitives'

/** PresetManager lists the service-template catalog and lets the user add or remove
 *  their own entries. Built-in presets belong to the binary, so they are shown but
 *  cannot be deleted. Changes persist immediately, like the autostart toggle, rather
 *  than waiting for the drawer's Save button. */
export function PresetManager() {
  const [presets, setPresets] = useState<Preset[] | undefined>(undefined)
  const [name, setName] = useState('')
  const [protocol, setProtocol] = useState<Protocol>('tcp')
  const [port, setPort] = useState('')
  const [error, setError] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)

  const load = (signal?: AbortSignal) =>
    api
      .presets()
      .then((list) => {
        if (!signal?.aborted) setPresets(list)
      })
      .catch((cause: unknown) => {
        if (!signal?.aborted) setError(cause instanceof Error ? cause.message : String(cause))
      })

  useEffect(() => {
    const ctrl = new AbortController()
    void load(ctrl.signal)
    return () => ctrl.abort()
  }, [])

  const portNum = Number(port)
  const canAdd = name.trim() !== '' && isPort(portNum) && !busy

  const add = async () => {
    if (!canAdd) return
    setBusy(true)
    setError(undefined)
    try {
      await api.createPreset({ name: name.trim(), protocol, remotePort: portNum })
      setName('')
      setPort('')
      setProtocol('tcp')
      await load()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id: string) => {
    setBusy(true)
    setError(undefined)
    try {
      await api.deletePreset(id)
      await load()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    // Shut by default: presets are defaults for the add-forward dialog, edited once and
    // then left alone, so they are the last thing worth the vertical space on a card
    // whose subject is the forwards that are running.
    <details className="advanced">
      <summary>Service presets</summary>
      <div className="advanced-body">
        {error ? <Notice tone="error">{error}</Notice> : null}
        {presets === undefined ? (
          <div className="picker" aria-busy="true">
            <span className="skeleton wide" />
            <span className="skeleton wide" />
            <span className="skeleton half" />
            <span className="sr-only">Loading presets…</span>
          </div>
        ) : (
          <div className="picker">
            {presets.map((p) => (
              <div key={p.id} className="picker-item static">
                <span className="title">{p.name}</span>
                <span className="sub">
                  {p.protocol === 'both' ? 'tcp + udp' : p.protocol.toUpperCase()} {p.remotePort}
                </span>
                <span className="spacer" />
                {p.builtIn ? (
                  <span className="sub">built-in</span>
                ) : (
                  <button
                    className="btn ghost small"
                    disabled={busy}
                    onClick={() => void remove(p.id)}
                  >
                    Delete
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="inline-form">
          <label className="grow-2">
            <span>Name</span>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label>
            <span>Protocol</span>
            <select value={protocol} onChange={(e) => setProtocol(e.target.value as Protocol)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">Both</option>
            </select>
          </label>
          <label className="grow-1">
            <span>Port</span>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </label>
          <button className="btn small" disabled={!canAdd} onClick={() => void add()}>
            Add
          </button>
        </div>
        <span className="hint">
          Presets prefill the protocol and port in the add-forward dialog. Deleting one never
          touches existing forwards.
        </span>
      </div>
    </details>
  )
}
