// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { api, ApiError, type IPSFeedView } from '../api'
import { Notice, Scrim } from './primitives'
import { CloseIcon } from './shell/icons'

/** IpsFeedDialog adds or edits one feed of addresses. There is no format to choose, unlike a
 *  blocklist: every feed of this kind is one address or one network per line, and one that is
 *  something else is one this side cannot use whatever it says it is. */
export function IpsFeedDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: IPSFeedView | undefined
  onClose: () => void
  onSaved: () => void
}) {
  const isEdit = editing !== undefined
  const [name, setName] = useState(editing?.name ?? '')
  const [url, setUrl] = useState(editing?.url ?? '')
  const [error, setError] = useState<string | undefined>(undefined)
  const [saving, setSaving] = useState(false)

  // Escape closes, matching every other dialog the user has ever used.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const canSave = name.trim() !== '' && url.trim() !== '' && !saving

  const save = async () => {
    if (!canSave) return
    setSaving(true)
    setError(undefined)
    try {
      const feed = { name: name.trim(), url: url.trim() }
      if (isEdit) {
        await api.updateIpsFeed(editing.id, feed)
      } else {
        await api.createIpsFeed(feed)
      }
      onSaved()
      onClose()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Scrim onClose={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={isEdit ? 'Edit feed' : 'Add feed'}
      >
        <div className="overlay-head">
          <h2>{isEdit ? 'Edit feed' : 'Add feed'}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          {error ? <Notice tone="error">{error}</Notice> : null}

          <div className="form-grid">
            <div className="field span-2">
              <label htmlFor="ips-feed-name">Name</label>
              <input
                id="ips-feed-name"
                type="text"
                value={name}
                placeholder="My feed"
                onChange={(e) => setName(e.target.value)}
              />
              <span className="hint">Only a label. It is what the switch above shows.</span>
            </div>

            <div className="field span-2">
              <label htmlFor="ips-feed-url">Address</label>
              <input
                id="ips-feed-url"
                type="text"
                value={url}
                placeholder="https://example.com/addresses.txt"
                onChange={(e) => setUrl(e.target.value)}
              />
              <span className="hint">
                The file is downloaded over HTTPS and kept on this machine. HTTPS is required
                rather than preferred: what this file holds decides which connections are
                refused, so anyone able to rewrite it in transit would decide that instead.
              </span>
            </div>
          </div>

          <span className="hint">
            One address or one network per line, with comments after # or ;. Private, reserved
            and tailnet ranges are left out of a feed no matter what it says: these files carry
            them on purpose, and applying them would refuse your own network. The card above
            shows how many entries of each feed survived that.
          </span>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!canSave} onClick={() => void save()}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Add feed'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
