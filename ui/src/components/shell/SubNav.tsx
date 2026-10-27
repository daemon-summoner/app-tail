// SPDX-License-Identifier: MIT

import { href, type SectionId } from '../../lib/router'

/**
 * SubNav is the second column: the pages inside one section, one link each.
 *
 * It is shared rather than written per section so that two second columns cannot drift
 * apart in markup, in the class names the stylesheet keys on, or in which link carries
 * aria-current.
 */
export function SubNav<Id extends string>({
  section,
  heading,
  ids,
  labels,
  current,
  landing,
}: {
  section: SectionId
  /** What the column is called, above the links. */
  heading: string
  ids: readonly Id[]
  labels: Record<Id, string>
  /** Absent when the section's own landing page is open rather than one of its pages. */
  current: Id | undefined
  /** The page the section's bare address means, when it has one. Its link is that bare
   *  address, so the two ways of reaching it are one entry in the browser's history. */
  landing?: Id | undefined
}) {
  return (
    <nav className="subnav" aria-label={`${heading} sections`}>
      <h2 className="subnav-head">{heading}</h2>
      {ids.map((id) => {
        const here = id === current
        return (
          <a
            key={id}
            className={here ? 'subnav-item here' : 'subnav-item'}
            href={id === landing ? href(section) : href(section, id)}
            {...(here ? { 'aria-current': 'page' as const } : {})}
          >
            {labels[id]}
          </a>
        )
      })}
    </nav>
  )
}
