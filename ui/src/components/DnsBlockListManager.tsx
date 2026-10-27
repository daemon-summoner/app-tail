// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type DNSBlockListView } from '../api'
import { groupByProvider } from '../lib/catalog'
import { BlocklistGroup } from './BlocklistGroup'
import { DnsBlockListDialog } from './DnsBlockListDialog'
import { Notice } from './primitives'

/** DnsBlockListManager lists the whole catalog and lets the user add, change or remove
 *  their own entries. The shipped lists belong to the binary, so they are shown but can be
 *  neither edited nor deleted -- they are what blocking falls back to when a list somebody
 *  added is the one that broke a site. Changes persist immediately; the switches on the
 *  card above read the same catalog. */
export function DnsBlockListManager({
  lists,
  onChanged,
}: {
  lists: readonly DNSBlockListView[]
  onChanged: () => void
}) {
  const [editing, setEditing] = useState<DNSBlockListView | undefined>(undefined)
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)

  const remove = async (list: DNSBlockListView) => {
    setBusy(true)
    setError(undefined)
    try {
      await api.deleteBlocklist(list.id)
      onChanged()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    // Shut by default: the catalog is edited once and then left alone, while the switches
    // above it are what this card is opened for.
    <details className="advanced">
      <summary>Your blocklists</summary>
      <div className="advanced-body">
        {error ? <Notice tone="error">{error}</Notice> : null}

        <div className="picker">
          {groupByProvider(lists).map((group) => (
            <BlocklistGroup
              key={group.provider}
              provider={group.provider}
              count={group.items.length}
              defaultOpen={group.items.some((list) => !list.builtIn)}
            >
              {group.items.map((list) => (
                <div key={list.id} className="picker-item static">
                  <span className="title">{list.name}</span>
                  <span className="sub mono">{list.url}</span>
                  <span className="spacer" />
                  {list.builtIn ? (
                    <span className="sub">built-in</span>
                  ) : (
                    <>
                      <button
                        className="btn ghost small"
                        disabled={busy}
                        aria-label={`Edit ${list.name}`}
                        onClick={() => setEditing(list)}
                      >
                        Edit
                      </button>
                      <button
                        className="btn ghost small"
                        disabled={busy}
                        aria-label={`Delete ${list.name}`}
                        onClick={() => void remove(list)}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </div>
              ))}
            </BlocklistGroup>
          ))}
        </div>

        <button className="btn small" disabled={busy} onClick={() => setAdding(true)}>
          Add a list
        </button>
        <span className="hint">
          A list is a name and the address the file is downloaded from. A list that is switched
          on cannot be deleted: switch it off above first.
        </span>

        {adding || editing ? (
          <DnsBlockListDialog
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
