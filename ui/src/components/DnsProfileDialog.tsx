// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { api, ApiError, type DNSProfile } from '../api'
import { Notice, Scrim } from './primitives'
import { CloseIcon } from './shell/icons'

/** SERVER_SLOTS is how many resolvers one profile can name. It matches the catalog's own
 *  limit, so the form cannot compose a profile the agent refuses to store. */
const SERVER_SLOTS = 4

/** The rows start at one server plus one empty row to type the backup into: a profile with
 *  a single resolver is the common case, and a form that opens with four empty boxes reads
 *  as four things that have to be filled in. */
function slotsFrom(profile: DNSProfile | undefined): string[] {
  const servers = profile?.servers ?? []
  if (servers.length === 0) return ['']
  return servers.length < SERVER_SLOTS ? [...servers, ''] : [...servers]
}

export function DnsProfileDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: DNSProfile | undefined
  onClose: () => void
  onSaved: () => void
}) {
  const isEdit = editing !== undefined
  const [name, setName] = useState(editing?.name ?? '')
  const [servers, setServers] = useState<string[]>(() => slotsFrom(editing))
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

  const setServer = (index: number, value: string) =>
    setServers((prev) => prev.map((server, i) => (i === index ? value : server)))

  const filled = servers.map((s) => s.trim()).filter((s) => s !== '')
  const canSave = name.trim() !== '' && filled.length > 0 && !saving

  const save = async () => {
    if (!canSave) return
    setSaving(true)
    setError(undefined)
    try {
      const profile = { name: name.trim(), servers: filled }
      if (isEdit) {
        await api.updateDnsProfile(editing.id, profile)
      } else {
        await api.createDnsProfile(profile)
      }
      onSaved()
      onClose()
    } catch (cause) {
      // The agent names the server it could not make sense of, which is the only thing that
      // tells someone which of four boxes to fix.
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
        aria-label={isEdit ? 'Edit DNS profile' : 'Add DNS profile'}
      >
        <div className="overlay-head">
          <h2>{isEdit ? 'Edit DNS profile' : 'Add DNS profile'}</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          {error ? <Notice tone="error">{error}</Notice> : null}

          <div className="form-grid">
            <div className="field span-2">
              <label htmlFor="dns-profile-name">Name</label>
              <input
                id="dns-profile-name"
                type="text"
                value={name}
                placeholder="NextDNS"
                onChange={(e) => setName(e.target.value)}
              />
              <span className="hint">Only a label. It is what the picker and the menu bar show.</span>
            </div>

            {servers.map((server, index) => (
              <div className="field span-2" key={index}>
                <label htmlFor={`dns-profile-server-${index}`}>
                  {index === 0 ? 'Server' : `Backup server ${index}`}
                </label>
                <input
                  id={`dns-profile-server-${index}`}
                  type="text"
                  value={server}
                  placeholder={
                    index === 0 ? '1.1.1.1, tls://one.one.one.one or https://dns.example/dns-query' : 'optional'
                  }
                  onChange={(e) => setServer(index, e.target.value)}
                />
              </div>
            ))}

            {/* The agent hides the part of a DoH URL that identifies the account using it,
                because its answer goes to every process on this machine. Unexplained, a box
                reading ".../..." looks like a stored value that got mangled, and the next
                thing someone does is retype it from memory. */}
            {servers.some((server) => server.trim().endsWith('/...')) ? (
              <div className="field span-2">
                <span className="hint">
                  A server ending in <span className="mono">/...</span> hides the part of its
                  address that identifies your account. Leave it exactly as it is to keep
                  resolving through it, or type the full URL to change it.
                </span>
              </div>
            ) : null}

            {servers.length < SERVER_SLOTS ? (
              <div className="field span-2">
                <button className="btn ghost small" onClick={() => setServers((prev) => [...prev, ''])}>
                  Add another server
                </button>
              </div>
            ) : null}
          </div>

          <span className="hint">
            Servers are tried in order, and app-tail stays on the one that answers rather than
            racing them: a resolver that blocks a domain has to be the one that answers, or it
            blocks nothing. A plain address is <span className="mono">1.1.1.1</span> or{' '}
            <span className="mono">1.1.1.1:53</span>; DNS over TLS is{' '}
            <span className="mono">tls://one.one.one.one</span>; DNS over HTTPS is{' '}
            <span className="mono">https://dns.example/dns-query</span>.
          </span>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!canSave} onClick={() => void save()}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Add profile'}
          </button>
        </div>
      </div>
    </Scrim>
  )
}
