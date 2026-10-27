// SPDX-License-Identifier: MIT

import { resources, type ResourceKey, type ResourceTable } from './resources'

/** Poll is what a screen reads: the last value, the last failure, and whether anything
 *  has arrived yet. `loading` is true only until the first result, so a refresh never
 *  puts a settled screen back into its skeleton. `failures` counts the polls that have
 *  failed in a row -- the last good value is kept beside an error, so it is the only thing
 *  telling a screen apart from a screen whose agent stopped answering an hour ago. */
export interface Poll<T> {
  data: T | undefined
  error: string | undefined
  loading: boolean
  failures: number
  refresh: () => void
}

/** consecutiveFailuresBeforeBackoff is how many failures in a row it takes before the
 *  store slows down. Below it the poll keeps its cadence: one failed request is usually a
 *  restart, and backing off immediately would make a two-second outage look like a
 *  thirty-second one. It is exported because it is also the count at which a screen may
 *  say the agent is gone: the same evidence, read once. */
export const consecutiveFailuresBeforeBackoff = 3

/** maxBackoffMs bounds how far apart a failing poll drifts. An agent that comes back has
 *  to be noticed without the user reloading the page. */
const maxBackoffMs = 30_000

type Listener = () => void

/** entry is one key's shared state: the timer, the subscribers and the last answer. */
interface Entry {
  readonly key: ResourceKey
  readonly fetch: () => Promise<unknown>
  readonly intervalMs: number
  /** snapshot is handed to useSyncExternalStore, so its identity changes only when
   *  something in it changed -- a fresh object per read would re-render every consumer on
   *  every render. */
  snapshot: Poll<unknown>
  listeners: Set<Listener>
  timer: ReturnType<typeof setTimeout> | undefined
  /** inFlight is what makes two screens asking at once one request rather than two. */
  inFlight: boolean
  failures: number
  /** generation is bumped when a result stops being wanted, so a slow response cannot
   *  overwrite the value a later refresh already delivered. */
  generation: number
}

/** reason renders whatever a rejected fetch carried. `fetch` rejects with a plain string
 *  or a DOMException often enough that assuming an Error would render "undefined" where
 *  the cause belongs. */
function reason(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}

/**
 * PollStore is the dashboard's one connection to the agent.
 *
 * It replaces a poll per screen with a poll per key: subscribers are counted, so a key
 * nobody is looking at stops being asked for; a request already in flight is shared rather
 * than repeated; and a key read by two screens at once costs one timer and one request.
 *
 * It is deliberately not a module-level singleton. The test suite clears globals between
 * files but not module state, so a shared instance would carry one test's cached responses
 * into the next. Every consumer reaches it through the provider, and a component rendered
 * without one fails loudly rather than silently polling nothing.
 */
export class PollStore {
  private readonly entries = new Map<ResourceKey, Entry>()

  /** watching is how many keys currently have subscribers. The document listener is
   *  attached while it is above zero and removed when it returns to zero, which keeps the
   *  store from outliving its consumers -- including across a StrictMode remount, where a
   *  listener attached in a constructor would be attached twice. */
  private watching = 0

  private readonly onVisibilityChange = () => {
    if (!document.hidden) this.refreshAll()
  }

  /** registry is where a key's fetch and its cadence come from. It defaults to the app's
   *  own, and is a parameter so the store's timing -- backoff, dedupe, the hidden-tab
   *  skip -- can be driven against fetchers a test controls rather than through fetch. */
  constructor(private readonly registry: ResourceTable = resources) {}

  /** subscribe registers a listener for one key and starts polling it if nothing else
   *  was. The returned function is the only way polling stops. */
  subscribe(key: ResourceKey, listener: Listener): () => void {
    const entry = this.entryFor(key)
    entry.listeners.add(listener)
    if (entry.listeners.size === 1) this.start(entry)

    return () => {
      if (!entry.listeners.delete(listener)) return
      if (entry.listeners.size === 0) this.stop(entry)
    }
  }

  /** snapshot is the current value for a key. It is safe to call before subscribing:
   *  an unread key reports itself as still loading, which is what a first paint shows. */
  snapshot(key: ResourceKey): Poll<unknown> {
    return this.entryFor(key).snapshot
  }

  /** refresh asks for one key again now, without waiting for its next tick. Every
   *  mutation the dashboard makes ends in one of these. */
  refresh(key: ResourceKey): void {
    void this.run(this.entryFor(key))
  }

  /** refreshAll asks for every key something is watching. Keys nobody is looking at are
   *  left alone: fetching them would be work for a screen that is not on. */
  refreshAll(): void {
    for (const entry of this.entries.values()) {
      if (entry.listeners.size > 0) void this.run(entry)
    }
  }

  /**
   * invalidate marks every key under a prefix as out of date.
   *
   * A watched key is re-read at once, because something is showing it. An unwatched one
   * has its cached value dropped instead, so the screen that reads it next starts from
   * the agent rather than from whatever was true before the write.
   */
  invalidate(prefix: string): void {
    for (const entry of this.entries.values()) {
      if (!entry.key.startsWith(prefix)) continue
      if (entry.listeners.size > 0) {
        void this.run(entry)
        continue
      }
      entry.generation += 1
      entry.failures = 0
      this.publish(entry, { data: undefined, error: undefined, loading: true, failures: 0 })
    }
  }

  private entryFor(key: ResourceKey): Entry {
    const existing = this.entries.get(key)
    if (existing !== undefined) return existing

    const resource = this.registry[key]
    const entry: Entry = {
      key,
      fetch: resource.fetch,
      intervalMs: resource.intervalMs,
      snapshot: {
        data: undefined,
        error: undefined,
        loading: true,
        failures: 0,
        // Bound once so the snapshot's identity does not change with every publish for a
        // reason no consumer cares about.
        refresh: () => this.refresh(key),
      },
      listeners: new Set(),
      timer: undefined,
      inFlight: false,
      failures: 0,
      generation: 0,
    }
    this.entries.set(key, entry)
    return entry
  }

  private start(entry: Entry): void {
    this.watching += 1
    if (this.watching === 1) {
      // Coming back to a tab whose ticks were skipped is the only thing that can close
      // the gap; without this the dashboard shows whatever was true when the user last
      // looked, possibly a connected node that has since dropped.
      document.addEventListener('visibilitychange', this.onVisibilityChange)
    }
    void this.run(entry)
  }

  private stop(entry: Entry): void {
    if (entry.timer !== undefined) {
      clearTimeout(entry.timer)
      entry.timer = undefined
    }
    // The value is kept rather than cleared: a screen returning to a key it read a moment
    // ago should show what it had while the fresh read is on its way.
    this.watching -= 1
    if (this.watching === 0) {
      document.removeEventListener('visibilitychange', this.onVisibilityChange)
    }
  }

  /** arm schedules the next attempt. A chain of timeouts rather than an interval, because
   *  the delay changes as a key starts failing and an interval cannot. */
  private arm(entry: Entry): void {
    if (entry.timer !== undefined) clearTimeout(entry.timer)
    entry.timer = setTimeout(() => {
      entry.timer = undefined
      // A dashboard left open in a background tab must not keep asking the agent for
      // status every two seconds for the rest of the day.
      if (document.hidden) {
        this.arm(entry)
        return
      }
      void this.run(entry)
    }, this.delayFor(entry))
  }

  private delayFor(entry: Entry): number {
    if (entry.failures < consecutiveFailuresBeforeBackoff) return entry.intervalMs
    const slowed = entry.intervalMs * 2 ** (entry.failures - consecutiveFailuresBeforeBackoff + 1)
    return Math.min(maxBackoffMs, slowed)
  }

  private async run(entry: Entry): Promise<void> {
    // A request already on its way is the answer to this one too.
    if (entry.inFlight) return
    entry.inFlight = true
    const generation = entry.generation

    try {
      const data = await entry.fetch()
      if (generation !== entry.generation) return
      entry.failures = 0
      this.publish(entry, { data, error: undefined, loading: false, failures: 0 })
    } catch (cause) {
      if (generation !== entry.generation) return
      entry.failures += 1
      // The last good value is kept beside the error: a card that emptied itself every
      // time one poll failed would flicker through a restart that changed nothing.
      this.publish(entry, {
        data: entry.snapshot.data,
        error: reason(cause),
        loading: false,
        failures: entry.failures,
      })
    } finally {
      entry.inFlight = false
      if (entry.listeners.size > 0) this.arm(entry)
    }
  }

  private publish(entry: Entry, next: Omit<Poll<unknown>, 'refresh'>): void {
    entry.snapshot = { ...next, refresh: entry.snapshot.refresh }
    for (const listener of entry.listeners) listener()
  }
}
