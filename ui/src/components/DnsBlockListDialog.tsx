// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { api, ApiError, type DNSBlockListView } from '../api'
import { Notice, Scrim } from './primitives'
import { CloseIcon } from './shell/icons'

/** The formats a list file can be written in, in the order the picker offers them.
 *  Reading the file is the first choice because it is right for almost every list; the
 *  other two are there for a file whose first lines do not say what it is. */
const FORMATS = [
  { value: 'auto', label: 'Work it out from the file' },
  { value: 'hosts', label: 'Hosts file' },
  { value: 'abp', label: 'Adblock Plus filters' },
] as const

export function DnsBlockListDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: DNSBlockListView | undefined
  onClose: () => void
  onSaved: () => void
}) {
  const isEdit = editing !== undefined
  const [name, setName] = useState(editing?.name ?? '')
  const [url, setUrl] = useState(editing?.url ?? '')
  const [format, setFormat] = useState(editing?.format ?? 'auto')
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
      const list = { name: name.trim(), url: url.trim(), format }
      if (isEdit) {
        await api.updateBlocklist(editing.id, list)
      } else {
        await api.createBlocklist(list)
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
        aria-label={isEdit ? 'Edit blocklist' : 'Add blocklist'}
      >
        <div className="overlay-head">
          <h2>{isEdit ? 'Edit blocklist' : 'Add blocklist'}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          {error ? <Notice tone="error">{error}</Notice> : null}

          <div className="form-grid">
            <div className="field span-2">
              <label htmlFor="blocklist-name">Name</label>
              <input
                id="blocklist-name"
                type="text"
                value={name}
                placeholder="My list"
                onChange={(e) => setName(e.target.value)}
              />
              <span className="hint">Only a label. It is what the switch above shows.</span>
            </div>

            <div className="field span-2">
              <label htmlFor="blocklist-url">Address</label>
              <input
                id="blocklist-url"
                type="text"
                value={url}
                placeholder="https://example.com/blocklist.txt"
                onChange={(e) => setUrl(e.target.value)}
              />
              <span className="hint">
                The file is downloaded over HTTPS and kept on this machine, so the site it comes
                from is asked once a day rather than once a query.
              </span>
            </div>

            <div className="field span-2">
              <label htmlFor="blocklist-format">Written as</label>
              <select
                id="blocklist-format"
                value={format}
                onChange={(e) => setFormat(e.target.value)}
              >
                {FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <span className="hint">
            A resolver can act on the names in a list and nothing else, so the rules in a
            browser filter list that match a path, an element or a page's own address are
            counted and dropped. The card above shows how many of each list survived.
          </span>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!canSave} onClick={() => void save()}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Add list'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
