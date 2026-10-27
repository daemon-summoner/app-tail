// SPDX-License-Identifier: MIT

import { useState, type ReactNode } from 'react'

/** BlocklistGroup is one publisher's run of rows, behind a heading that opens and closes
 *  it. The catalog ships forty-odd lists from a dozen publishers, so every group open at
 *  once is a wall nobody reads; `defaultOpen` is how a caller says "this is the group
 *  they came for" -- the one holding a list already on, or the one holding their own
 *  lists. It is an initial state rather than a prop the card keeps enforcing, so a poll
 *  that refreshes the catalog cannot close a group somebody just opened.
 *
 *  `noun` is what the count is counting, because the same grouping shows two catalogs: the
 *  lists of names blocking downloads, and the feeds of addresses inspection downloads. */
export function BlocklistGroup({
  provider,
  count,
  defaultOpen,
  noun = 'list',
  children,
}: {
  provider: string
  count: number
  defaultOpen: boolean
  noun?: string
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div role="group" aria-label={provider}>
      <button
        type="button"
        className="picker-group"
        aria-expanded={open}
        onClick={() => setOpen((was) => !was)}
      >
        <span className="picker-caret" aria-hidden="true" />
        <span className="title">{provider}</span>
        <span className="count">
          {count} {count === 1 ? noun : `${noun}s`}
        </span>
      </button>
      {open ? children : null}
    </div>
  )
}
