// SPDX-License-Identifier: MIT

// Adding one proxy instance: what to call it, and nothing else.
//
// The short name and the address it binds are both derivable -- the agent makes a handle
// out of the name and takes the next port nothing has asked for -- and everything else is a
// field of the instance form, filled in on its card under the same labels, help and
// validation a later edit uses. A second form here would be a second place for them to
// drift.
//
// It is added with no rules, so it reaches nothing until somebody grants it something. A
// default grant would make the least-configured instance the most powerful one.

import { useEffect, useState } from 'react'
import { api, ApiError, type ProxyInstanceView } from '../../api'
import { Notice, Scrim } from '../primitives'
import { CloseIcon } from '../shell/icons'

export function AddProxyDialog({
  onClose,
  onAdded,
}: {
  onClose: () => void
  onAdded: (added: ProxyInstanceView) => void
}) {
  const [name, setName] = useState('')
  const [error, setError] = useState<string | undefined>(undefined)
  const [saving, setSaving] = useState(false)

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
      onAdded(await api.createProxy({ name: name.trim() }))
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  const title = 'Add a proxy'
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
              <label htmlFor="proxy-name">Name</label>
              <input
                id="proxy-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <span className="hint">
                Naming it after the program you will point at it is what makes a list of
                proxies readable. The short handle it answers to in its addresses is made
                from this, and both can be changed afterwards.
              </span>
            </div>
          </div>

          <p className="hint">
            It is added with no rules, so it reaches nothing until you grant it something.
            The next screen is where that is done.
          </p>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={saving || name.trim() === ''}
            onClick={() => void save()}
          >
            {saving ? 'Adding…' : 'Add proxy'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
