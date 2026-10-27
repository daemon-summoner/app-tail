// SPDX-License-Identifier: MIT

// What two networks carrying the same addresses means, said on the page that lists them.
//
// It sits above the connections rather than on one of them because that is what the
// problem is: a range is contested between connections, and the one holding it looks
// perfectly healthy from its own page. Without this, the second network connects, reports
// itself connected, and every address on it silently answers from the first.

import { Notice } from '../primitives'
import type { FabricClaimant, FabricView } from '../../api'

/** nameOf is what a conflicting connection is called, falling back to its id: a sentence
 *  naming an identifier is worse than one naming nothing, and there is nothing else. */
function nameOf(claimant: FabricClaimant): string {
  return claimant.name ?? claimant.tunnelId
}

/** namesOf reads a list of connections as a person would say it. */
function namesOf(claimants: readonly FabricClaimant[]): string {
  const names = claimants.map(nameOf)
  if (names.length <= 1) return names.join('')
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

export function AddressConflicts({ view }: { view: FabricView | undefined }) {
  if (view === undefined) return null
  const conflicts = view.conflicts ?? []
  const unread = view.unread ?? []
  if (conflicts.length === 0 && unread.length === 0) return null

  return (
    <>
      {conflicts.length > 0 ? (
        <Notice tone="warn">
          <p>
            {conflicts.length === 1
              ? 'Two of these networks carry the same addresses, and only one of them can be reached at them.'
              : `${conflicts.length} address ranges are carried by more than one of these networks, and only one connection can be reached at each.`}
          </p>
          <ul>
            {conflicts.map((conflict) => (
              <li key={conflict.prefix}>
                {conflict.detail}, so{' '}
                {conflict.claimants?.length ? namesOf(conflict.claimants) : 'the others'} cannot be
                reached at {conflict.prefix} while both are connected.
              </li>
            ))}
          </ul>
        </Notice>
      ) : null}

      {/* A connection that cannot say what it carries leaves a gap in the report above,
          and a gap there looks exactly like no conflict at all. */}
      {unread.map((connection) => (
        <Notice key={connection.tunnelId} tone="error">
          The networks {connection.name ?? connection.tunnelId} carries could not be read, so a
          range it collides with would not be reported: {connection.error}
        </Notice>
      ))}
    </>
  )
}
