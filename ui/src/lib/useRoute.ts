// SPDX-License-Identifier: MIT

import { useMemo, useSyncExternalStore } from 'react'

import { legacyHash, movedTo, parseRoute, type Route } from './router'

// One window listener for the whole app, however many components ask where they are:
// hashchange fires on every navigation, and a listener per subscriber would multiply the
// work of moving between two pages by the number of things that render differently on
// each. The listener is attached with the first subscriber and removed with the last.

const listeners = new Set<() => void>()

function notify() {
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  if (listeners.size === 1) window.addEventListener('hashchange', notify)
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0) window.removeEventListener('hashchange', notify)
  }
}

/** currentHash is the address to render. A document with no hash at all may still be
 *  carrying the menu bar's query string, and that has to decide the first paint rather
 *  than be corrected after one. An address that has moved renders where it moved to, for
 *  the same reason: a stale bookmark should land on the page, not on a corrected one. */
function currentHash(): string {
  const asked =
    window.location.hash !== '' ? window.location.hash : (legacyHash(window.location.search) ?? '#/')
  return movedTo(asked) ?? asked
}

/** useRoute is where every component asks what page it is on. */
export function useRoute(): Route {
  const hash = useSyncExternalStore(subscribe, currentHash)
  return useMemo(() => parseRoute(hash), [hash])
}

/** useAskedHash is the address in the URL bar, before any moved address is resolved to
 *  where it now lives. Two moved addresses can render the same page, so the resolved
 *  route is the wrong thing to watch for whether the URL bar still names a page that
 *  moved -- moving between them leaves it unchanged. */
export function useAskedHash(): string {
  return useSyncExternalStore(subscribe, () => window.location.hash)
}
