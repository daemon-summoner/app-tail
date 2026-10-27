// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type IPSFeedView } from '../api'
import { groupByProvider } from '../lib/catalog'
import { BlocklistGroup } from './BlocklistGroup'
import { IpsFeedDialog } from './IpsFeedDialog'
import { Notice } from './primitives'

/** IpsFeedManager lists the whole catalog of address feeds and lets the user add, change or
 *  remove their own entries. The shipped feeds belong to the binary, so they are shown but can
 *  be neither edited nor deleted -- they are what inspection falls back to when a feed somebody
 *  added is the one that refused a site. Changes persist immediately; the switches on the card
 *  above read the same catalog. */
export function IpsFeedManager({
  feeds,
  onChanged,
}: {
  feeds: readonly IPSFeedView[]
  onChanged: () => void
}) {
  const [editing, setEditing] = useState<IPSFeedView | undefined>(undefined)
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)

  const remove = async (feed: IPSFeedView) => {
    setBusy(true)
    setError(undefined)
    try {
      await api.deleteIpsFeed(feed.id)
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
      <summary>Your feeds</summary>
      <div className="advanced-body">
        {error ? <Notice tone="error">{error}</Notice> : null}

        <div className="picker">
          {groupByProvider(feeds).map((group) => (
            <BlocklistGroup
              key={group.provider}
              provider={group.provider}
              count={group.items.length}
              noun="feed"
              defaultOpen={group.items.some((feed) => !feed.builtIn)}
            >
              {group.items.map((feed) => (
                <div key={feed.id} className="picker-item static">
                  <span className="title">{feed.name}</span>
                  <span className="sub mono">{feed.url}</span>
                  <span className="spacer" />
                  {feed.builtIn ? (
                    <span className="sub">built-in</span>
                  ) : (
                    <>
                      <button
                        className="btn ghost small"
                        disabled={busy}
                        aria-label={`Edit ${feed.name}`}
                        onClick={() => setEditing(feed)}
                      >
                        Edit
                      </button>
                      <button
                        className="btn ghost small"
                        disabled={busy}
                        aria-label={`Delete ${feed.name}`}
                        onClick={() => void remove(feed)}
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
          Add a feed
        </button>
        <span className="hint">
          A feed is a name and the address the file is downloaded from. A feed that is switched
          on cannot be deleted: switch it off above first.
        </span>

        {adding || editing ? (
          <IpsFeedDialog
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
