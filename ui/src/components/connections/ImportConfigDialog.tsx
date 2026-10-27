// SPDX-License-Identifier: MIT

// Reading a server's own configuration file into a connection.
//
// Nobody transcribes one of these by hand: the server issues a file and it is pasted here
// whole. The text goes to the agent unread, so the format is understood in exactly one
// place and a directive this app cannot honour comes back named instead of being quietly
// dropped by a second parser living in the dashboard.

import { useEffect, useState } from 'react'

import { api, ApiError, type TunnelType, type TunnelView } from '../../api'
import { Notice, Scrim } from '../primitives'
import { CloseIcon } from '../shell/icons'

/** What the file to paste looks like, in the words of whoever issued it. The two formats
 *  have nothing in common but that a server hands them out, so describing them as one
 *  "configuration file" would leave the reader checking the wrong file for the wrong
 *  opening line. */
function fileHint(type: TunnelType) {
  if (type === 'openvpn') {
    return (
      <>
        Paste the whole <code>.ovpn</code> file the server gave you, including its{' '}
        <code>&lt;ca&gt;</code> and <code>&lt;cert&gt;</code> blocks. Its keys are stored here
        and never shown again.
      </>
    )
  }
  return (
    <>
      Paste the whole file the server gave you — the one beginning <code>[Interface]</code> and
      carrying a <code>[Peer]</code> section. Its keys are stored here and never shown again.
    </>
  )
}

/** The paste box, shared by the Add flow and by a connection's own page so a file is
 *  described the same way whichever of the two the reader arrived through. */
export function ConfigFileField({
  id,
  type,
  value,
  onChange,
}: {
  id: string
  type: TunnelType
  value: string
  onChange: (text: string) => void
}) {
  return (
    <div className="field span-2">
      <label htmlFor={id}>Configuration file</label>
      <textarea
        id={id}
        className="config-file"
        rows={10}
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {/* In the hint rather than in the box itself: text inside the box disappears the
          moment someone starts typing, which is exactly when they are checking it. */}
      <span className="hint">{fileHint(type)}</span>
    </div>
  )
}

/**
 * Reading a file into a connection that already exists: replacing a rotated key, or
 * pointing an existing connection at a different server.
 *
 * The whole file replaces what the connection was configured with. A file describes one
 * server completely, so merging it with what is already there would leave a connection
 * that is part one server and part another.
 */
export function ImportConfigDialog({
  tunnel,
  onClose,
  onImported,
}: {
  tunnel: TunnelView
  onClose: () => void
  onImported: (imported: TunnelView) => void
}) {
  const [file, setFile] = useState('')
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
      onImported(await api.importTunnel(tunnel.id, file))
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  const title = `Import a configuration into ${tunnel.name}`
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
            <ConfigFileField
              id="tunnel-import-file"
              type={tunnel.type}
              value={file}
              onChange={setFile}
            />
          </div>

          <p className="hint">
            This replaces everything the connection is configured with, and reconnects it.
          </p>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={saving || file.trim() === ''}
            onClick={() => void save()}
          >
            {saving ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
