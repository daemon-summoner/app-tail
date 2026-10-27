// SPDX-License-Identifier: MIT

// Adding one connection: what kind of network it is, what to call it, and -- where the
// server issues one -- the configuration file it gave you.
//
// Beyond that it asks for nothing. Everything that makes a connection actually connect --
// the control plane, the credentials, the routes it accepts -- is a field of the connection
// form, so it is filled in on the connection's own page under the same labels, the same
// help and the same validation a later edit uses. A second form here would be a second
// place for those fields to drift. The file is the exception because it is not a form: it
// is one paste that fills every field at once, and it is where the reader already is.

import { useEffect, useState } from 'react'
import { api, ApiError, type TunnelTypeInfo, type TunnelView } from '../../api'
import { Notice, Scrim } from '../primitives'
import { ConfigFileField } from './ImportConfigDialog'
import { canImportConfig } from './tunnel'
import { CloseIcon } from '../shell/icons'

/** What the agent said, or what went wrong reaching it. */
function messageOf(cause: unknown): string {
  return cause instanceof ApiError ? cause.message : String(cause)
}

export function AddConnectionDialog({
  offer,
  onClose,
  onAdded,
}: {
  offer: TunnelTypeInfo
  onClose: () => void
  onAdded: (added: TunnelView) => void
}) {
  const [name, setName] = useState('')
  const [file, setFile] = useState('')
  const [error, setError] = useState<string | undefined>(undefined)
  const [saving, setSaving] = useState(false)
  const importable = canImportConfig(offer.value)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const save = async () => {
    setSaving(true)
    setError(undefined)
    try {
      const added = await api.createTunnel({ type: offer.value, name: name.trim() })
      // Blank means no file was pasted. What was pasted goes on untouched: the agent reads
      // the file, and a dashboard that tidied it first would be reading it too.
      if (file.trim() === '') {
        onAdded(added)
        return
      }
      // A file the agent refuses leaves nothing behind. The connection was created a moment
      // ago to have something to import into, so it is taken away again rather than left on
      // the list as an empty entry nobody asked for.
      try {
        onAdded(await api.importTunnel(added.id, file))
      } catch (cause) {
        const refusal = messageOf(cause)
        try {
          await api.deleteTunnel(added.id)
          setError(refusal)
        } catch (undo) {
          // Both, because the first says why the file was refused and the second says that
          // a connection nobody asked for is now on the list.
          setError(`${refusal} The connection it was being read into is still there: ${messageOf(undo)}`)
        }
        return
      }
    } catch (cause) {
      setError(messageOf(cause))
    } finally {
      setSaving(false)
    }
  }

  const title = `Add a ${offer.label} connection`
  return (
    <Scrim onClose={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="overlay-head">
          <h2>{title}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          {error ? <Notice tone="error">{error}</Notice> : null}

          <div className="form-grid">
            <div className="field span-2">
              <label htmlFor="tunnel-name">Name (optional)</label>
              <input
                id="tunnel-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <span className="hint">
                What this network is called here, “{offer.label}” if left blank. The short name
                it answers to in DNS is made from it, and both can be changed afterwards.
              </span>
            </div>

            {importable ? (
              <ConfigFileField
                id="tunnel-add-file"
                type={offer.value}
                value={file}
                onChange={setFile}
              />
            ) : null}
          </div>

          <p className="hint">
            {importable
              ? 'The file is optional here. Without one the connection is added switched on but not yet configured, and the next screen is where it is told how to reach the network.'
              : 'It is added switched on but not yet configured, so the next screen is where it is told how to reach the network.'}
          </p>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={saving} onClick={() => void save()}>
            {saving ? 'Adding…' : 'Add connection'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
