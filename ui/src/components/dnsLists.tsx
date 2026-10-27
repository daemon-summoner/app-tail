// SPDX-License-Identifier: MIT

// The list shape both DNS cards render: a titled column of names with what it means
// behind an info button, or a sentence saying why it is empty.

import { InfoPopover } from './InfoPopover'

/** One list with what it means, or the sentence that says it is empty. A blank column
 *  reads as a page that failed to load, and each of these is empty for its own reason. */
export function Names({
  title,
  hint,
  items,
  empty,
}: {
  title: string
  hint: string
  items: string[]
  empty: string
}) {
  return (
    <div className="dns-list">
      <div className="list-head">
        <h3>{title}</h3>
        {/* What the column means never changes; which names are in it is the answer. */}
        <InfoPopover label={title}>
          <p>{hint}</p>
        </InfoPopover>
      </div>
      {items.length > 0 ? (
        <ul>
          {items.map((item) => (
            <li key={item} className="mono">
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="dns-empty">{empty}</p>
      )}
    </div>
  )
}
