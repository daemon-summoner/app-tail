// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type DNSProfile } from '../api'
import { DnsProfileDialog } from './DnsProfileDialog'
import { Notice } from './primitives'

/** DnsProfileManager lists the resolver catalog and lets the user add, change or remove
 *  their own entries. Built-in profiles belong to the binary, so they are shown but can be
 *  neither edited nor deleted -- they are the way back when a custom profile is what broke
 *  resolution. Changes persist immediately; the picker above reads the same catalog. */
export function DnsProfileManager({
  profiles,
  onChanged,
}: {
  profiles: readonly DNSProfile[]
  onChanged: () => void
}) {
  const [editing, setEditing] = useState<DNSProfile | undefined>(undefined)
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)

  const remove = async (profile: DNSProfile) => {
    setBusy(true)
    setError(undefined)
    try {
      await api.deleteDnsProfile(profile.id)
      onChanged()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    // Shut by default: the catalog is edited once and then left alone, while the picker
    // above it is the thing this card is opened for.
    <details className="advanced">
      <summary>Your DNS profiles</summary>
      <div className="advanced-body">
        {error ? <Notice tone="error">{error}</Notice> : null}

        <div className="picker">
          {profiles.map((profile) => (
            <div key={profile.id} className="picker-item static">
              <span className="title">{profile.name}</span>
              <span className="sub mono">{(profile.servers ?? []).join(', ')}</span>
              <span className="spacer" />
              {profile.builtIn ? (
                <span className="sub">built-in</span>
              ) : (
                <>
                  <button
                    className="btn ghost small"
                    disabled={busy}
                    aria-label={`Edit ${profile.name}`}
                    onClick={() => setEditing(profile)}
                  >
                    Edit
                  </button>
                  <button
                    className="btn ghost small"
                    disabled={busy}
                    aria-label={`Delete ${profile.name}`}
                    onClick={() => void remove(profile)}
                  >
                    Delete
                  </button>
                </>
              )}
            </div>
          ))}
        </div>

        <button className="btn small" disabled={busy} onClick={() => setAdding(true)}>
          Add a profile
        </button>
        <span className="hint">
          A profile is a name and up to four servers, tried in order. Plain addresses, DNS over
          TLS and DNS over HTTPS all work. The profile this machine is resolving through cannot
          be deleted while it is in use: pick another one in the list above first.
        </span>

        {adding || editing ? (
          <DnsProfileDialog
            editing={editing}
            onClose={() => {
              setAdding(false)
              setEditing(undefined)
            }}
            onSaved={onChanged}
          />
        ) : null}
      </div>
    </details>
  )
}
