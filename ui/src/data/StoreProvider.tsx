// SPDX-License-Identifier: MIT

import { createContext, useContext, useMemo, useSyncExternalStore, type ReactNode } from 'react'

import { PollStore, type Poll } from './store'
import type { ResourceData, ResourceKey } from './resources'

/** The context has no default value on purpose. A component that polls without a provider
 *  above it is a wiring mistake, and the alternative -- a lazily created module-level
 *  store -- would hide it while leaking one screen's cached responses into the next. */
const StoreContext = createContext<PollStore | undefined>(undefined)

/** StoreProvider owns the one store everything below it reads through. */
export function StoreProvider({
  store,
  children,
}: {
  /** store is accepted so a test can hold the same instance it renders against. Left out,
   *  the provider makes its own and keeps it for the life of the mount. */
  store?: PollStore | undefined
  children: ReactNode
}) {
  const own = useMemo(() => store ?? new PollStore(), [store])
  return <StoreContext.Provider value={own}>{children}</StoreContext.Provider>
}

/** useStore is how a component reaches the shared store for the things a snapshot cannot
 *  express: refreshing everything after a save, or invalidating a group of keys. */
export function useStore(): PollStore {
  const store = useContext(StoreContext)
  if (store === undefined) {
    throw new Error(
      'no StoreProvider above this component: it reads from the agent, so it has to be ' +
        'rendered inside one',
    )
  }
  return store
}

/**
 * usePolled reads one key and re-renders when it changes.
 *
 * The subscription is what starts and stops the poll, so a screen that stops rendering
 * this stops costing requests. Two components reading the same key share one timer and one
 * request rather than each running their own.
 */
export function usePolled<K extends ResourceKey>(key: K): Poll<ResourceData<K>> {
  const store = useStore()
  const snapshot = useSyncExternalStore(
    useMemo(() => (listener: () => void) => store.subscribe(key, listener), [store, key]),
    () => store.snapshot(key),
  )
  return snapshot as Poll<ResourceData<K>>
}
